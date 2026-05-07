<?php

declare(strict_types=1);

namespace Semitexa\Rbac\Application\Service;

use Psr\Container\ContainerInterface;
use Semitexa\Authorization\Domain\Contract\SubjectGrantResolverInterface;
use Semitexa\Authorization\Domain\Model\CapabilityGrantSet;
use Semitexa\Authorization\Domain\Model\PermissionGrantSet;
use Semitexa\Authorization\Domain\Model\SubjectGrantSet;
use Semitexa\Core\Attribute\InjectAsReadonly;
use Semitexa\Core\Attribute\SatisfiesServiceContract;
use Semitexa\Core\Auth\AuthSubjectType;
use Semitexa\Core\Authorization\SubjectInterface;
use Semitexa\Core\Container\SemitexaContainer;
use Semitexa\Core\Environment;
use Semitexa\Core\Tenant\Layer\OrganizationLayer;
use Semitexa\Core\Tenant\TenantContextStoreInterface;
use Semitexa\Rbac\Domain\Contract\CapabilityProviderInterface;
use Semitexa\Rbac\Domain\Contract\PermissionProviderInterface;
use Semitexa\Rbac\Domain\Contract\ServiceCapabilityProviderInterface;

/**
 * Resolves capability and permission grants for a subject.
 *
 * Routes by AuthSubjectType:
 *   User    → PermissionProviderInterface + CapabilityProviderInterface
 *   Service → ServiceCapabilityProviderInterface (no permissions — service
 *             permissions are not modeled today; service auth is capability-
 *             based)
 *   null    → defaults to User for backwards compatibility with callers
 *             that built AuthenticatedSubject without a subject type
 *
 * Cache key:
 *   {tenantId|'-'}:{subjectType}:{identifier}
 *
 * Composing the key from the tenant id, the subject type and the identifier
 * prevents three distinct collision modes:
 *   1. A User principal and a Service principal sharing the same textual id
 *      (e.g. "partner-x") from silently overwriting each other's grants.
 *   2. The same subject id resolved under two different tenants (e.g. an
 *      admin tool iterating tenants in one process, or two concurrent
 *      requests from different tenants for the same service receiver) from
 *      seeing each other's grants.
 *   3. CLI / single-tenant code paths (where `TenantContextStore::tryGet()`
 *      returns null) are stamped with `-` so they never collide with a
 *      legitimately tenanted entry. RbacCacheKeyCollisionTest pins the
 *      contract.
 */
#[SatisfiesServiceContract(of: SubjectGrantResolverInterface::class)]
final class SubjectGrantResolver implements SubjectGrantResolverInterface
{
    #[InjectAsReadonly]
    protected ContainerInterface $container;

    public function resolve(SubjectInterface $subject): SubjectGrantSet
    {
        if ($subject->isGuest()) {
            return new SubjectGrantSet(
                new CapabilityGrantSet([]),
                new PermissionGrantSet([]),
            );
        }

        $userId = $subject->getIdentifier() ?? '';
        $subjectType = $subject->getSubjectType() ?? AuthSubjectType::User;
        $tenantId = $this->resolveTenantId();
        $cacheKey = self::cacheKey($subjectType, $userId, $tenantId);

        $cached = RbacDecisionCache::get($cacheKey);
        if ($cached !== null) {
            return $cached;
        }

        if ($subjectType === AuthSubjectType::User
            && $this->isDemoRolePermissionsEnabled()
            && str_starts_with($userId, 'google:')
        ) {
            $permissions = $this->resolveDemoRolePermissions($userId);
            if ($permissions !== null) {
                $grants = new SubjectGrantSet(
                    new CapabilityGrantSet([]),
                    new PermissionGrantSet($permissions),
                );
                RbacDecisionCache::set($cacheKey, $grants);
                return $grants;
            }
        }

        $grants = $this->buildGrants($userId, $subjectType, $tenantId);
        RbacDecisionCache::set($cacheKey, $grants);
        return $grants;
    }

    /**
     * Compose the cache key. Public so other rbac code (audit, debug, tests)
     * can derive the same key without re-implementing the rule.
     *
     * `tenantId === null` is encoded as a literal `-` so untenanted entries
     * cannot accidentally compare equal to an entry under a tenant whose id
     * also happens to be empty. The tenant component sits FIRST so a future
     * cache scan / per-tenant invalidation can prefix-match cheaply.
     */
    public static function cacheKey(AuthSubjectType $subjectType, string $identifier, ?string $tenantId = null): string
    {
        $tenantPart = $tenantId !== null && $tenantId !== '' ? $tenantId : '-';
        return $tenantPart . ':' . $subjectType->value . ':' . $identifier;
    }

    private function buildGrants(string $subjectId, AuthSubjectType $subjectType, ?string $tenantId): SubjectGrantSet
    {
        if ($subjectType === AuthSubjectType::Service) {
            return new SubjectGrantSet(
                capabilities: new CapabilityGrantSet($this->resolveServiceCapabilities($subjectId, $tenantId)),
                // Service permissions are intentionally NOT modeled today —
                // service auth is capability-based. PermissionProviderInterface
                // is the user-domain contract; running it for a Service id
                // would either return spurious user grants OR pollute the user
                // permission audit trail. Empty is the safe default; introduce
                // a ServicePermissionProviderInterface here if the model ever
                // grows.
                permissions: new PermissionGrantSet([]),
            );
        }

        // AuthSubjectType::User (or null defaulted to User above)
        return new SubjectGrantSet(
            capabilities: new CapabilityGrantSet($this->resolveCapabilities($subjectId)),
            permissions: new PermissionGrantSet($this->resolvePermissions($subjectId)),
        );
    }

    /**
     * @return list<\Semitexa\Authorization\Domain\Contract\CapabilityInterface>
     */
    private function resolveCapabilities(string $userId): array
    {
        $providers = $this->getProviders(CapabilityProviderInterface::class);
        $capabilities = [];
        $seen = [];
        foreach ($providers as $provider) {
            foreach ($provider->getCapabilitiesForUser($userId) as $capability) {
                $key = $capability::class . ':' . ($capability instanceof \BackedEnum
                    ? (string) $capability->value
                    : (string) spl_object_id($capability));
                if (isset($seen[$key])) {
                    continue;
                }
                $seen[$key] = true;
                $capabilities[] = $capability;
            }
        }
        return $capabilities;
    }

    /**
     * @return list<\Semitexa\Authorization\Domain\Contract\CapabilityInterface>
     */
    private function resolveServiceCapabilities(string $serviceId, ?string $tenantId): array
    {
        $providers = $this->getProviders(ServiceCapabilityProviderInterface::class);
        $capabilities = [];
        $seen = [];
        foreach ($providers as $provider) {
            foreach ($provider->getCapabilitiesForService($serviceId, $tenantId) as $capability) {
                $key = $capability::class . ':' . ($capability instanceof \BackedEnum
                    ? (string) $capability->value
                    : (string) spl_object_id($capability));
                if (isset($seen[$key])) {
                    continue;
                }
                $seen[$key] = true;
                $capabilities[] = $capability;
            }
        }
        return $capabilities;
    }

    /**
     * Resolve the current tenant id via the framework's tenant context store
     * if one is wired. Returns null when no tenant has been resolved (CLI
     * tasks without `tenant:run`, single-tenant deployments, system tasks).
     *
     * Reads the OrganizationLayer of the active context — that's the
     * cross-package contract from semitexa-core. Avoids coupling to the
     * concrete TenantContext class in semitexa-tenancy.
     */
    private function resolveTenantId(): ?string
    {
        $store = $this->tryResolve(TenantContextStoreInterface::class);
        if (!$store instanceof TenantContextStoreInterface) {
            return null;
        }
        $context = $store->tryGet();
        if ($context === null) {
            return null;
        }
        $orgLayer = new OrganizationLayer();
        if (!$context->hasLayer($orgLayer)) {
            return null;
        }
        $value = $context->getLayer($orgLayer);
        if ($value === null) {
            return null;
        }
        $raw = $value->rawValue();
        return $raw !== '' ? $raw : null;
    }

    /** @return list<string> */
    private function resolvePermissions(string $userId): array
    {
        // Permission providers are additive — every module that registers a
        // PermissionProviderInterface contributes the slugs it knows for the
        // subject, and the union becomes the effective grant set. Anything
        // narrower would let a process-local test fixture (AuthDemo's store)
        // shadow the real backing store (Playground's role catalog) just
        // because it ranks higher in module-order, which is the bug
        // [403 on /playground/rbac/action/users-manage for the seeded
        // Super Admin] this resolver was originally producing.
        $slugs = [];
        $hasProvider = false;
        foreach ($this->getProviders(PermissionProviderInterface::class) as $provider) {
            $hasProvider = true;
            foreach ($provider->getPermissionsForUser($userId) as $slug) {
                $slugs[$slug] = true;
            }
        }

        if ($hasProvider) {
            return array_keys($slugs);
        }

        // Legacy bridge: when no PermissionProviderInterface is installed,
        // platform-user may still expose RbacServiceInterface. Kept for
        // hosts that haven't migrated yet — additive providers above are
        // the canonical path.
        $legacyRbacClass = 'Semitexa\\Platform\\User\\Domain\\Service\\RbacServiceInterface';
        $legacyRbac = $this->tryResolve($legacyRbacClass);
        if ($legacyRbac !== null && method_exists($legacyRbac, 'getUserPermissions')) {
            $permissions = [];
            foreach ($legacyRbac->getUserPermissions($userId) as $perm) {
                if (method_exists($perm, 'getSlug')) {
                    $permissions[] = $perm->getSlug();
                } elseif (isset($perm->slug)) {
                    $permissions[] = $perm->slug;
                }
            }
            return $permissions;
        }

        return [];
    }

    /**
     * Enumerate every container-registered implementation of an additive
     * provider contract. Falls back to the active-only binding when the
     * container does not expose the chain — keeps SubjectGrantResolver
     * usable from unit tests that hand it a vanilla PSR-11 container.
     *
     * @template T of object
     * @param class-string<T> $interface
     * @return list<T>
     */
    private function getProviders(string $interface): array
    {
        // method_exists fallback: composer.json allows `semitexa/core: "*"`,
        // and `getAllImplementationsOf` is only present on cores that ship
        // additive-contract enumeration. Older cores still satisfy the
        // SemitexaContainer instanceof check, so call it only when present
        // and degrade to the single active binding otherwise.
        if (isset($this->container)
            && $this->container instanceof SemitexaContainer
            // PHPStan against the current core narrows the SemitexaContainer
            // type so method_exists() is always-true. On older cores the
            // method is genuinely absent and method_exists() is the load-
            // bearing guard. Use the tolerant `-next-line` form (no
            // identifier) so PHPStan/core combos that *don't* emit
            // `function.alreadyNarrowedType` won't blow up on
            // `ignore.unmatchedIdentifier`.
            // @phpstan-ignore-next-line
            && method_exists($this->container, 'getAllImplementationsOf')
        ) {
            return $this->container->getAllImplementationsOf($interface);
        }
        $single = $this->tryResolve($interface);
        return $single instanceof $interface ? [$single] : [];
    }

    /**
     * @return list<string>|null
     */
    private function resolveDemoRolePermissions(string $userId): ?array
    {
        $provider = $this->tryResolve(DemoRolePermissionProvider::class);
        if (! $provider instanceof DemoRolePermissionProvider) {
            $provider = new DemoRolePermissionProvider();
        }

        return $provider->getPermissionsForUser($userId);
    }

    private function isDemoRolePermissionsEnabled(): bool
    {
        $appEnv = strtolower(Environment::getEnvValue('APP_ENV', 'prod') ?? 'prod');

        return $appEnv !== 'prod'
            || Environment::getEnvValue('DEMO_RBAC_ENABLED', 'false') === 'true';
    }

    private function tryResolve(string $class): ?object
    {
        if (!isset($this->container)) {
            return null;
        }
        try {
            $instance = $this->container->get($class);
            return is_object($instance) ? $instance : null;
        } catch (\Throwable) {
            return null;
        }
    }
}

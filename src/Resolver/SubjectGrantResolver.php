<?php

declare(strict_types=1);

namespace Semitexa\Rbac\Resolver;

use Psr\Container\ContainerInterface;
use Semitexa\Authorization\Authorizer\SubjectGrantResolverInterface;
use Semitexa\Authorization\Grant\CapabilityGrantSet;
use Semitexa\Authorization\Grant\PermissionGrantSet;
use Semitexa\Authorization\Grant\SubjectGrantSet;
use Semitexa\Core\Attribute\InjectAsReadonly;
use Semitexa\Core\Attribute\SatisfiesServiceContract;
use Semitexa\Core\Authorization\SubjectInterface;
use Semitexa\Rbac\Capability\CapabilityRegistryInterface;
use Semitexa\Rbac\Contract\PermissionProviderInterface;
use Semitexa\Rbac\Runtime\RbacDecisionCache;

/**
 * Resolves capability and permission grants for a subject.
 *
 * Delegates permission lookup to PermissionProviderInterface (implemented by
 * semitexa-platform-user or any other RBAC backend). Results are cached per
 * request per user via RbacDecisionCache.
 */
#[SatisfiesServiceContract(of: SubjectGrantResolverInterface::class)]
final class SubjectGrantResolver implements SubjectGrantResolverInterface
{
    #[InjectAsReadonly]
    protected ?ContainerInterface $container = null;

    public function resolve(SubjectInterface $subject): SubjectGrantSet
    {
        if ($subject->isGuest()) {
            return new SubjectGrantSet(
                new CapabilityGrantSet([]),
                new PermissionGrantSet([]),
            );
        }

        $userId = $subject->getIdentifier() ?? '';

        $cached = RbacDecisionCache::get($userId);
        if ($cached !== null) {
            return $cached;
        }

        $grants = $this->buildGrants($userId);
        RbacDecisionCache::set($userId, $grants);
        return $grants;
    }

    private function buildGrants(string $userId): SubjectGrantSet
    {
        $permissions = $this->resolvePermissions($userId);

        return new SubjectGrantSet(
            capabilities: new CapabilityGrantSet([]),
            permissions: new PermissionGrantSet($permissions),
        );
    }

    /** @return list<string> */
    private function resolvePermissions(string $userId): array
    {
        // Try PermissionProviderInterface first (clean RBAC contract)
        $provider = $this->tryResolve(PermissionProviderInterface::class);
        if ($provider instanceof PermissionProviderInterface) {
            return $provider->getPermissionsForUser($userId);
        }

        // Fallback: delegate to platform-user's RbacServiceInterface (legacy bridge)
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

    private function tryResolve(string $class): ?object
    {
        if ($this->container === null) {
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

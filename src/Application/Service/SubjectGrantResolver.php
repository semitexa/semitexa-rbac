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
use Semitexa\Core\Authorization\SubjectInterface;
use Semitexa\Rbac\Domain\Contract\PermissionProviderInterface;

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

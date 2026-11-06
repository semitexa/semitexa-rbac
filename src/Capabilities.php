<?php

declare(strict_types=1);

namespace Semitexa\Rbac;

use Semitexa\Core\Attribute\Capability;

/**
 * What this package offers, for the capability catalog.
 *
 * Without this the package is invisible to anyone whose project has not
 * installed it - which is precisely the audience worth telling, since they are
 * the ones about to build it by hand. The convention is one `Capabilities` class
 * per package: a definite place to look, and a definite place for a guard to
 * check.
 *
 * Nothing reads this at runtime.
 */
#[Capability(
    id: 'rbac.roles',
    summary: 'Roles granting permissions and capabilities, resolved into the grant set the authorizer asks for.',
    useWhen: 'Access depends on named roles that someone administers, not on properties of the record.',
    avoidWhen: 'Grants come from somewhere else already - ownership, a plan tier, an external identity provider.',
    replaces: [
        'a roles column parsed into an array and compared by string in each check',
        'a permission matrix kept in a config file and in a database, drifting apart',
    ],
    seeAlso: 'semitexa/authorization',
    usage: <<<'USAGE'
        // Stored roles: require semitexa/platform-user, which this package does not install, run orm:sync, then:
        bin/semitexa role:create clerk -p orders.manage --shared
        bin/semitexa role:assign clerk --email=ada@shop.test

        // Or roles of your own. Without the attribute it is never asked; with it, all providers' slugs add up.
        #[SatisfiesServiceContract(of: PermissionProviderInterface::class)]
        final class ShopRoleProvider implements PermissionProviderInterface
        {
            #[InjectAsReadonly]
            protected ShopRoleStore $roles;
            #[InjectAsReadonly]
            protected TenantContextStoreInterface $tenants;

            public function getPermissionsForUser(string $userId): array
            {
                // Silent: the call names no tenant. Looked up by user alone, a role from one tenant grants in all.
                return $this->roles->slugsOf($userId, TenantContextAccess::tenantId($this->tenants->tryGet()));
            }
        }

        // A handler writes nothing: a guest gets a 401, a user without the slug a 403, before it runs.
        #[RequiresPermission('orders.manage')]
        #[AsProtectedPayload(path: '/orders', methods: ['POST'], responseWith: OrdersResource::class)]
        final class ManageOrdersPayload {}
        // Roles here grant slugs: a #[RequiresCapability] route stays 403 until a CapabilityProviderInterface of yours grants it.
        USAGE,
)]
final class Capabilities
{
}

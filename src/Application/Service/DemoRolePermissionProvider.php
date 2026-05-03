<?php

declare(strict_types=1);

namespace Semitexa\Rbac\Application\Service;

final class DemoRolePermissionProvider
{
    private const DEMO_ROLE_PERMISSIONS = [
        'admin' => ['products.read', 'products.write', 'users.manage', 'orders.manage', 'settings.manage'],
        'editor' => ['products.read', 'products.write'],
        'viewer' => ['products.read'],
    ];

    /**
     * @return list<string>|null
     */
    public function getPermissionsForUser(string $userId): ?array
    {
        $parts = explode(':', $userId, 3);
        if (count($parts) !== 3) {
            return null;
        }

        [, , $role] = $parts;
        if (!isset(self::DEMO_ROLE_PERMISSIONS[$role])) {
            return null;
        }

        return self::DEMO_ROLE_PERMISSIONS[$role];
    }
}

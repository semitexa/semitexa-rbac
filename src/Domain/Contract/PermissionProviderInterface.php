<?php

declare(strict_types=1);

namespace Semitexa\Rbac\Domain\Contract;

/**
 * Provides permission slug lookup for an authenticated subject.
 *
 * Implemented by modules that manage role/permission storage (e.g. semitexa-platform-user).
 * SubjectGrantResolver delegates to this interface to resolve what permissions
 * a user holds, without coupling the RBAC layer to a specific ORM or data model.
 */
interface PermissionProviderInterface
{
    /**
     * Returns all permission slugs granted to the user identified by $userId.
     *
     * @return list<string>
     */
    public function getPermissionsForUser(string $userId): array;
}

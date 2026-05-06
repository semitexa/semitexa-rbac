<?php

declare(strict_types=1);

namespace Semitexa\Rbac\Domain\Contract;

use Semitexa\Authorization\Domain\Contract\CapabilityInterface;

/**
 * Provides capability lookup for an authenticated subject.
 *
 * Parallel to {@see PermissionProviderInterface}: applications register an
 * implementation that returns the CapabilityInterface enum cases granted to
 * a given user; SubjectGrantResolver assembles the resulting CapabilityGrantSet.
 *
 * Without an installed implementation, every subject receives an empty
 * capability grant set — meaning every #[RequiresCapability(...)] route
 * returns 403. Wiring a CapabilityProviderInterface is what turns capability
 * metadata into runtime authorization.
 */
interface CapabilityProviderInterface
{
    /**
     * @return list<CapabilityInterface> Capabilities the user holds. Order is
     *         not significant; the Authorizer uses identity comparison
     *         (`===`), which is the correct check for backed-enum capabilities
     *         (case singletons).
     */
    public function getCapabilitiesForUser(string $userId): array;
}

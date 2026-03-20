<?php

declare(strict_types=1);

namespace Semitexa\Rbac\Capability;

use Semitexa\Authorization\Capability\Capability;

/**
 * Registry mapping Capability enum cases to bitmask segment/bit positions.
 *
 * The bitmask layout is an implementation detail of semitexa-rbac.
 * Consumers interact with Capability values, not segment indices.
 */
interface CapabilityRegistryInterface
{
    /**
     * Returns true if the subject's capability bitmask satisfies the required capability.
     *
     * @param int[] $subjectSegments Bitmask segments from the subject's grant record
     */
    public function check(Capability $capability, array $subjectSegments): bool;
}

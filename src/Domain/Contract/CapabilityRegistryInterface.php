<?php

declare(strict_types=1);

namespace Semitexa\Rbac\Domain\Contract;

use Semitexa\Authorization\Domain\Contract\CapabilityInterface;

/**
 * Registry mapping CapabilityInterface enum cases to bitmask segment/bit positions.
 *
 * The bitmask layout is an implementation detail of semitexa-rbac.
 * Consumers interact with CapabilityInterface values, not segment indices.
 */
interface CapabilityRegistryInterface
{
    /**
     * Register a capability with its bitmask position.
     */
    public function register(CapabilityInterface $capability, int $segment, int $bit): void;

    /**
     * Returns true if the subject's capability bitmask satisfies the required capability.
     *
     * @param int[] $subjectSegments Bitmask segments from the subject's grant record
     */
    public function check(CapabilityInterface $capability, array $subjectSegments): bool;
}

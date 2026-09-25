<?php

declare(strict_types=1);

namespace Semitexa\Rbac\Application\Service;

use Semitexa\Rbac\Domain\Contract\CapabilityRegistryInterface;

use Semitexa\Authorization\Domain\Contract\CapabilityInterface;

/**
 * Default capability registry implementation.
 *
 * Capabilities are registered with a segment index and bit position.
 * The subject's capability grant is a list of integer segments; the registry
 * evaluates whether the required bit is set in the appropriate segment.
 *
 * This is the internal bitmask model. The public boundary remains CapabilityInterface enum values.
 */
final class CapabilityRegistry implements CapabilityRegistryInterface
{
    /**
     * @var array<string, array{segment: int, bit: int}>
     * Maps capability key (enum class + '::' + case name) to segment/bit position.
     */
    private array $map = [];

    /**
     * Register a capability with its bitmask position.
     *
     * @param CapabilityInterface $capability The enum case to register
     * @param int $segment           Zero-based segment index (each int = 32 bits)
     * @param int $bit               Zero-based bit position within the segment (0–31)
     */
    public function register(CapabilityInterface $capability, int $segment, int $bit): void
    {
        if ($segment < 0 || $bit < 0 || $bit > 31) {
            throw new \InvalidArgumentException(sprintf(
                'Capability %s cannot be registered at segment %d, bit %d: segments start at 0 and bits run 0-31.',
                $this->key($capability),
                $segment,
                $bit,
            ));
        }

        $key = $this->key($capability);

        // Two capabilities on one bit grant each other: whoever holds either
        // passes a check for both. Re-registering the SAME capability moves it.
        foreach ($this->map as $otherKey => $pos) {
            if ($otherKey !== $key && $pos['segment'] === $segment && $pos['bit'] === $bit) {
                throw new \InvalidArgumentException(sprintf(
                    'Capability %s cannot be registered at segment %d, bit %d: %s already occupies it.',
                    $key,
                    $segment,
                    $bit,
                    $otherKey,
                ));
            }
        }

        $this->map[$key] = ['segment' => $segment, 'bit' => $bit];
    }

    public function check(CapabilityInterface $capability, array $subjectSegments): bool
    {
        $key = $this->key($capability);

        if (!isset($this->map[$key])) {
            // Unregistered capability — deny by default.
            return false;
        }

        $pos = $this->map[$key];
        $segment = $subjectSegments[$pos['segment']] ?? 0;

        return (bool) ($segment & (1 << $pos['bit']));
    }

    private function key(CapabilityInterface $capability): string
    {
        if ($capability instanceof \UnitEnum) {
            return $capability::class . '::' . $capability->name;
        }

        if (method_exists($capability, 'name')) {
            return $capability::class . '::' . (string) $capability->name;
        }

        if (method_exists($capability, '__toString')) {
            return $capability::class . '::' . (string) $capability;
        }

        return $capability::class . '::' . spl_object_hash($capability);
    }
}

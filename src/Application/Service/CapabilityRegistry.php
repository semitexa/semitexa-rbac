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
        $this->map[$this->key($capability)] = ['segment' => $segment, 'bit' => $bit];
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
        return $capability::class . '::' . (method_exists($capability, 'name') ? $capability->name : (string) $capability);
    }
}

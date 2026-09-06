<?php

declare(strict_types=1);

namespace Semitexa\Rbac\Tests\Unit\Service;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Semitexa\Authorization\Domain\Contract\CapabilityInterface;
use Semitexa\Rbac\Application\Service\CapabilityRegistry;

/**
 * The bitmask that decides who may do what.
 *
 * This package shipped with no tests at all, which for a nine-file package is
 * unremarkable everywhere except here: a wrong bit is either an administrator
 * locked out or a stranger let in, and neither announces itself. Every case
 * below is about a way the arithmetic can be wrong quietly.
 */
final class CapabilityRegistryTest extends TestCase
{
    /**
     * The one that matters most: a capability nobody registered must be denied,
     * not defaulted to allowed. A typo in an enum case is otherwise a grant.
     */
    #[Test]
    public function an_unregistered_capability_is_denied(): void
    {
        $registry = new CapabilityRegistry();

        self::assertFalse(
            $registry->check(TestCapability::PublishArticle, [0xFFFFFFFF]),
            'an unknown capability must be denied even against an all-bits-set subject',
        );
    }

    #[Test]
    public function a_registered_bit_grants_when_the_subject_carries_it(): void
    {
        $registry = new CapabilityRegistry();
        $registry->register(TestCapability::PublishArticle, segment: 0, bit: 3);

        self::assertTrue($registry->check(TestCapability::PublishArticle, [1 << 3]));
        self::assertFalse($registry->check(TestCapability::PublishArticle, [0]));
    }

    /**
     * Segments are separate 32-bit words. The same bit position in the wrong
     * word must not grant — that is the failure that hands out a capability the
     * subject was never given.
     */
    #[Test]
    public function a_bit_set_in_another_segment_does_not_grant(): void
    {
        $registry = new CapabilityRegistry();
        $registry->register(TestCapability::PublishArticle, segment: 1, bit: 3);

        self::assertFalse(
            $registry->check(TestCapability::PublishArticle, [1 << 3, 0]),
            'the bit is set in segment 0; the capability lives in segment 1',
        );
        self::assertTrue($registry->check(TestCapability::PublishArticle, [0, 1 << 3]));
    }

    /**
     * A subject whose grant array is shorter than the segment being asked about
     * must be denied, not crash and not read a stray index.
     */
    #[Test]
    public function a_subject_missing_the_segment_is_denied(): void
    {
        $registry = new CapabilityRegistry();
        $registry->register(TestCapability::PublishArticle, segment: 4, bit: 0);

        self::assertFalse($registry->check(TestCapability::PublishArticle, []));
        self::assertFalse($registry->check(TestCapability::PublishArticle, [0xFFFFFFFF]));
    }

    /** The top of a 32-bit segment, where a sign-bit mistake would show. */
    #[Test]
    public function the_highest_bit_in_a_segment_still_works(): void
    {
        $registry = new CapabilityRegistry();
        $registry->register(TestCapability::PublishArticle, segment: 0, bit: 31);

        self::assertTrue($registry->check(TestCapability::PublishArticle, [1 << 31]));
        self::assertFalse($registry->check(TestCapability::PublishArticle, [1 << 30]));
    }

    /** Two capabilities in one segment must not answer for each other. */
    #[Test]
    public function neighbouring_capabilities_do_not_bleed(): void
    {
        $registry = new CapabilityRegistry();
        $registry->register(TestCapability::PublishArticle, segment: 0, bit: 0);
        $registry->register(TestCapability::DeleteArticle, segment: 0, bit: 1);

        $onlyPublish = [1 << 0];

        self::assertTrue($registry->check(TestCapability::PublishArticle, $onlyPublish));
        self::assertFalse(
            $registry->check(TestCapability::DeleteArticle, $onlyPublish),
            'publishing must not imply deleting',
        );
    }

    /**
     * Registering the same capability again moves it. A stale position left
     * behind would keep granting from the old bit.
     */
    #[Test]
    public function re_registering_a_capability_moves_it(): void
    {
        $registry = new CapabilityRegistry();
        $registry->register(TestCapability::PublishArticle, segment: 0, bit: 0);
        $registry->register(TestCapability::PublishArticle, segment: 0, bit: 5);

        self::assertFalse($registry->check(TestCapability::PublishArticle, [1 << 0]), 'the old bit must stop granting');
        self::assertTrue($registry->check(TestCapability::PublishArticle, [1 << 5]));
    }

    /**
     * Identity is the enum case, not the string. Two enums that happen to share
     * a case name are different capabilities.
     */
    #[Test]
    public function two_enums_sharing_a_case_name_are_different_capabilities(): void
    {
        $registry = new CapabilityRegistry();
        $registry->register(TestCapability::PublishArticle, segment: 0, bit: 2);

        self::assertFalse(
            $registry->check(OtherCapability::PublishArticle, [1 << 2]),
            'a case name from another enum must not inherit this grant',
        );
    }
}

enum TestCapability implements CapabilityInterface
{
    case PublishArticle;
    case DeleteArticle;
}

enum OtherCapability implements CapabilityInterface
{
    case PublishArticle;
}

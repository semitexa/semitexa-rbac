<?php

declare(strict_types=1);

namespace Semitexa\Rbac\Application\Service;

use Semitexa\Authorization\Domain\Model\SubjectGrantSet;

/**
 * Request-scoped, Swoole-coroutine-aware cache for resolved subject grants.
 *
 * Grant resolution (DB lookup) runs once per authenticated user per request.
 * The cache is isolated per Swoole coroutine and cleared between requests.
 * In CLI/test mode a static fallback is used.
 */
final class RbacDecisionCache
{
    private const KEY = '__rbac_grants';

    /** @var array<string, SubjectGrantSet> */
    private static array $staticFallback = [];

    public static function get(string $userId): ?SubjectGrantSet
    {
        if (self::inCoroutine()) {
            return \Swoole\Coroutine::getContext()[self::KEY][$userId] ?? null;
        }
        return self::$staticFallback[$userId] ?? null;
    }

    public static function set(string $userId, SubjectGrantSet $grants): void
    {
        if (self::inCoroutine()) {
            \Swoole\Coroutine::getContext()[self::KEY][$userId] = $grants;
            return;
        }
        self::$staticFallback[$userId] = $grants;
    }

    public static function clear(): void
    {
        if (self::inCoroutine()) {
            \Swoole\Coroutine::getContext()[self::KEY] = [];
            return;
        }
        self::$staticFallback = [];
    }

    private static function inCoroutine(): bool
    {
        return class_exists(\Swoole\Coroutine::class, false)
            && \Swoole\Coroutine::getCid() > 0;
    }
}

<?php

declare(strict_types=1);

namespace Semitexa\Rbac\Application\Service;

use Semitexa\Authorization\Domain\Model\SubjectGrantSet;
use Semitexa\Core\Lifecycle\PerRequestStateRegistry;

/**
 * Request-scoped, Swoole-coroutine-aware cache for resolved subject grants.
 *
 * Grant resolution (DB lookup) runs once per authenticated user per request.
 * The cache is isolated per Swoole coroutine (auto-cleared when the coroutine
 * ends) and, in CLI / queue-worker mode, resets via the framework's per-request
 * lifecycle registry — see {@see PerRequestStateRegistry} and the finally
 * blocks in Application::handleRequest and QueueWorker::processPayload.
 *
 * The first call to {@see set()} or {@see get()} registers a clear() callback
 * with the registry once per worker. Re-registration is a no-op so concurrent
 * first-touches in separate coroutines are safe.
 */
final class RbacDecisionCache
{
    private const KEY = '__rbac_grants';
    private const REGISTRY_NAME = 'rbac_decision_cache';

    /** @var array<string, SubjectGrantSet> */
    private static array $staticFallback = [];

    private static bool $registered = false;

    public static function get(string $userId): ?SubjectGrantSet
    {
        self::ensureRegistered();
        if (self::inCoroutine()) {
            return \Swoole\Coroutine::getContext()[self::KEY][$userId] ?? null;
        }
        return self::$staticFallback[$userId] ?? null;
    }

    public static function set(string $userId, SubjectGrantSet $grants): void
    {
        self::ensureRegistered();
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

    /**
     * Lazy registration with the framework's per-request lifecycle. Calling
     * this from get()/set() means the cache is only registered once a real
     * grant lookup happens — no overhead for workers that never authenticate.
     */
    private static function ensureRegistered(): void
    {
        if (self::$registered) {
            return;
        }
        self::$registered = true;
        PerRequestStateRegistry::register(
            self::REGISTRY_NAME,
            static function (): void {
                self::clear();
            },
        );
    }

    private static function inCoroutine(): bool
    {
        return class_exists(\Swoole\Coroutine::class, false)
            && \Swoole\Coroutine::getCid() > 0;
    }
}

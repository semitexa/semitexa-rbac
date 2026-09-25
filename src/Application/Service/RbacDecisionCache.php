<?php

declare(strict_types=1);

namespace Semitexa\Rbac\Application\Service;

use Semitexa\Authorization\Domain\Model\SubjectGrantSet;
use Semitexa\Core\Lifecycle\CurrentRequestStore;
use Semitexa\Core\Lifecycle\PerRequestStateRegistry;
use Semitexa\Core\Request;

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
 *
 * Entries are also bound to the request they were resolved for (the one in
 * {@see CurrentRequestStore}). A coroutine can outlive a request: a held-open
 * SSE connection re-runs its routes through RouteExecutor::reExecute() on its
 * own coroutine, each tick with a freshly rebuilt Request, and relies on that
 * re-authorization to terminate the stream once a permission is revoked. A
 * cache scoped only to the coroutine answered every tick with the grants
 * resolved when the stream opened, so a revoke was never seen.
 */
final class RbacDecisionCache
{
    private const KEY = '__rbac_grants';
    private const OWNER_KEY = '__rbac_grants_owner';
    private const REGISTRY_NAME = 'rbac_decision_cache';

    /** @var array<string, SubjectGrantSet> */
    private static array $staticFallback = [];

    /** @var \WeakReference<Request>|null */
    private static ?\WeakReference $staticOwner = null;

    private static bool $registered = false;

    public static function get(string $userId): ?SubjectGrantSet
    {
        self::ensureRegistered();
        self::dropIfRequestChanged();
        if (self::inCoroutine()) {
            return \Swoole\Coroutine::getContext()[self::KEY][$userId] ?? null;
        }
        return self::$staticFallback[$userId] ?? null;
    }

    public static function set(string $userId, SubjectGrantSet $grants): void
    {
        self::ensureRegistered();
        self::dropIfRequestChanged();
        if (self::inCoroutine()) {
            \Swoole\Coroutine::getContext()[self::KEY][$userId] = $grants;
            return;
        }
        self::$staticFallback[$userId] = $grants;
    }

    public static function clear(): void
    {
        if (self::inCoroutine()) {
            $context = \Swoole\Coroutine::getContext();
            $context[self::KEY] = [];
            unset($context[self::OWNER_KEY]);
            return;
        }
        self::$staticFallback = [];
        self::$staticOwner = null;
    }

    /**
     * Empty the cache when the current request is not the one its entries
     * were resolved for, and record the current request as the new owner.
     * The owner is held weakly: a request that has been freed can never
     * compare equal to a new one that happens to reuse its object id.
     */
    private static function dropIfRequestChanged(): void
    {
        $current = CurrentRequestStore::get();

        if (self::inCoroutine()) {
            $context = \Swoole\Coroutine::getContext();
            $owner = $context[self::OWNER_KEY] ?? null;
            if (self::ownedBy($owner instanceof \WeakReference ? $owner : null, $current)) {
                return;
            }
            $context[self::KEY] = [];
            $context[self::OWNER_KEY] = $current !== null ? \WeakReference::create($current) : null;
            return;
        }

        if (self::ownedBy(self::$staticOwner, $current)) {
            return;
        }
        self::$staticFallback = [];
        self::$staticOwner = $current !== null ? \WeakReference::create($current) : null;
    }

    /** @param \WeakReference<Request>|null $owner */
    private static function ownedBy(?\WeakReference $owner, ?Request $current): bool
    {
        if ($current === null) {
            return $owner === null;
        }

        return $owner !== null && $owner->get() === $current;
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

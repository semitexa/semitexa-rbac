<?php

declare(strict_types=1);

namespace Semitexa\Rbac\Application\Service;

use Semitexa\Authorization\Domain\Model\SubjectGrantSet;
use Semitexa\Core\Attribute\WorkerState;
use Semitexa\Core\Lifecycle\CurrentRequestStore;
use Semitexa\Core\Lifecycle\PerRequestStateRegistry;
use Semitexa\Core\Request;
use Semitexa\Core\Support\CoroutineLocal;

/**
 * Request-scoped, Swoole-coroutine-aware cache for resolved subject grants.
 *
 * Grant resolution (DB lookup) runs once per authenticated user per request.
 * Entries and their owner live in {@see CoroutineLocal}: isolated per Swoole
 * coroutine (auto-cleared when the coroutine ends) and, in CLI / queue-worker
 * mode, reset via the framework's per-request lifecycle registry — see {@see PerRequestStateRegistry} and the finally
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

    #[WorkerState('Records that the clear() resetter was registered once per worker; holds no request data.')]
    private static bool $registered = false;

    public static function get(string $userId): ?SubjectGrantSet
    {
        self::ensureRegistered();
        self::dropIfRequestChanged();

        return self::entries()[$userId] ?? null;
    }

    public static function set(string $userId, SubjectGrantSet $grants): void
    {
        self::ensureRegistered();
        self::dropIfRequestChanged();

        $entries = self::entries();
        $entries[$userId] = $grants;
        CoroutineLocal::set(self::KEY, $entries);
    }

    public static function clear(): void
    {
        CoroutineLocal::remove(self::KEY);
        CoroutineLocal::remove(self::OWNER_KEY);
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
        $owner = CoroutineLocal::get(self::OWNER_KEY);

        if (self::ownedBy($owner instanceof \WeakReference ? $owner : null, $current)) {
            return;
        }

        CoroutineLocal::remove(self::KEY);
        if ($current !== null) {
            CoroutineLocal::set(self::OWNER_KEY, \WeakReference::create($current));
        } else {
            CoroutineLocal::remove(self::OWNER_KEY);
        }
    }

    /** @return array<string, SubjectGrantSet> */
    private static function entries(): array
    {
        $entries = CoroutineLocal::get(self::KEY, []);

        return is_array($entries) ? $entries : [];
    }

    /** @param \WeakReference<object>|null $owner */
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
}

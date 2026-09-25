<?php

declare(strict_types=1);

namespace Semitexa\Rbac\Tests\Unit\Service;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Semitexa\Authorization\Domain\Model\AuthenticatedSubject;
use Semitexa\Core\Auth\AuthSubjectType;
use Semitexa\Core\Lifecycle\CurrentRequestStore;
use Semitexa\Core\Request;
use Semitexa\Core\Support\CoroutineLocal;
use Semitexa\Rbac\Application\Service\RbacDecisionCache;
use Semitexa\Rbac\Application\Service\SubjectGrantResolver;
use Semitexa\Rbac\Domain\Contract\PermissionProviderInterface;
use Swoole\Coroutine;

/**
 * The grant cache lives for one authorization pass over one request, not for
 * the coroutine that happens to run it.
 *
 * A held-open SSE connection re-runs its routes (RouteExecutor::reExecute) in
 * the connection's own long-lived coroutine, each tick with a freshly rebuilt
 * Request, precisely so that a revoked permission terminates the stream. A
 * cache scoped to the coroutine kept answering with the grants resolved when
 * the stream opened, so the revoke was never seen.
 */
final class RbacDecisionCacheTest extends TestCase
{
    protected function setUp(): void
    {
        RbacDecisionCache::clear();
        CurrentRequestStore::clear();
        CoroutineLocal::resetCliStore();
    }

    protected function tearDown(): void
    {
        RbacDecisionCache::clear();
        CurrentRequestStore::clear();
        CoroutineLocal::resetCliStore();
    }

    #[Test]
    public function a_revoked_permission_is_seen_by_the_next_request_in_the_same_worker_context(): void
    {
        [$observed] = $this->revokeBetweenTwoRequests();

        self::assertSame([true, false], $observed);
    }

    #[Test]
    public function a_revoked_permission_is_seen_by_the_next_request_in_the_same_coroutine(): void
    {
        if (!class_exists(Coroutine::class)) {
            self::markTestSkipped('Swoole is not installed');
        }

        $observed = null;
        Coroutine\run(function () use (&$observed): void {
            [$observed] = $this->revokeBetweenTwoRequests();
        });

        self::assertSame([true, false], $observed);
    }

    #[Test]
    public function grants_are_reused_within_one_request(): void
    {
        $provider = new MutablePermissionProvider(['reports.read']);
        $resolver = $this->resolver($provider);
        $subject = new AuthenticatedSubject('user-1', AuthSubjectType::User);

        CurrentRequestStore::set(new Request('GET', '/reports', [], [], [], [], []));
        $resolver->resolve($subject);
        $resolver->resolve($subject);

        self::assertSame(1, $provider->calls, 'one request must resolve grants once');
    }

    /** @return array{list<bool>} */
    private function revokeBetweenTwoRequests(): array
    {
        $provider = new MutablePermissionProvider(['reports.read']);
        $resolver = $this->resolver($provider);
        $subject = new AuthenticatedSubject('user-1', AuthSubjectType::User);
        $observed = [];

        CurrentRequestStore::set(new Request('GET', '/reports', [], [], [], [], []));
        $observed[] = $resolver->resolve($subject)->permissions->has('reports.read');

        $provider->permissions = [];

        // Next tick: a rebuilt request on the same coroutine, as reExecute does.
        CurrentRequestStore::set(new Request('GET', '/reports', [], [], [], [], []));
        $observed[] = $resolver->resolve($subject)->permissions->has('reports.read');

        return [$observed];
    }

    private function resolver(PermissionProviderInterface $provider): SubjectGrantResolver
    {
        $container = new class ($provider) implements ContainerInterface {
            public function __construct(private readonly PermissionProviderInterface $provider) {}

            public function get(string $id): mixed
            {
                if ($id === PermissionProviderInterface::class) {
                    return $this->provider;
                }
                throw new \RuntimeException("No binding for {$id}");
            }

            public function has(string $id): bool
            {
                return $id === PermissionProviderInterface::class;
            }
        };

        $resolver = new SubjectGrantResolver();
        (new \ReflectionProperty(SubjectGrantResolver::class, 'container'))->setValue($resolver, $container);

        return $resolver;
    }
}

final class MutablePermissionProvider implements PermissionProviderInterface
{
    public int $calls = 0;

    /** @param list<string> $permissions */
    public function __construct(public array $permissions) {}

    public function getPermissionsForUser(string $userId): array
    {
        $this->calls++;

        return $this->permissions;
    }
}

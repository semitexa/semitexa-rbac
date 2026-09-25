<?php

declare(strict_types=1);

namespace Semitexa\Rbac\Tests\Unit\Service;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Semitexa\Rbac\Application\Service\SubjectGrantResolver;

/**
 * Demo roles turn any `google:*:admin`-shaped id into an administrator, so the
 * environments that enable them without an opt-in must be named, not inferred.
 */
final class DemoRoleEnvironmentTest extends TestCase
{
    private string|false $appEnv;
    private string|false $demoFlag;

    protected function setUp(): void
    {
        $this->appEnv = getenv('APP_ENV');
        $this->demoFlag = getenv('DEMO_RBAC_ENABLED');
        putenv('DEMO_RBAC_ENABLED');
    }

    protected function tearDown(): void
    {
        putenv($this->appEnv === false ? 'APP_ENV' : 'APP_ENV=' . $this->appEnv);
        putenv($this->demoFlag === false ? 'DEMO_RBAC_ENABLED' : 'DEMO_RBAC_ENABLED=' . $this->demoFlag);
    }

    /** @return iterable<string, array{string, bool}> */
    public static function environments(): iterable
    {
        yield 'dev' => ['dev', true];
        yield 'local' => ['local', true];
        yield 'test' => ['test', true];
        yield 'testing' => ['testing', true];
        yield 'prod' => ['prod', false];
        yield 'production' => ['production', false];
        yield 'staging' => ['staging', false];
        yield 'uppercase prod' => ['PROD', false];
    }

    #[Test]
    #[DataProvider('environments')]
    public function demo_roles_are_enabled_only_in_named_non_production_environments(string $env, bool $expected): void
    {
        putenv('APP_ENV=' . $env);

        self::assertSame($expected, $this->enabled());
    }

    #[Test]
    public function the_explicit_flag_still_enables_them_anywhere(): void
    {
        putenv('APP_ENV=staging');
        putenv('DEMO_RBAC_ENABLED=true');

        self::assertTrue($this->enabled());
    }

    private function enabled(): bool
    {
        $resolver = (new \ReflectionClass(SubjectGrantResolver::class))->newInstanceWithoutConstructor();

        return (new \ReflectionMethod(SubjectGrantResolver::class, 'isDemoRolePermissionsEnabled'))->invoke($resolver);
    }
}

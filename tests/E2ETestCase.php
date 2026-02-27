<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Tests;

use Illuminate\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Orchestra\Testbench\TestCase as BaseTestCase;
use Workbench\App\Providers\WorkbenchServiceProvider;

/**
 * TestCase for E2E tests: workbench routes + real in-memory DB + auth configured.
 */
abstract class E2ETestCase extends BaseTestCase
{
    /**
     * @param  Application  $app
     * @return array<int, class-string<ServiceProvider>>
     */
    protected function getPackageProviders($app): array
    {
        return [
            \CodeLieutenant\LaravelCrypto\ServiceProvider::class,
            WorkbenchServiceProvider::class,
        ];
    }

    protected function defineRoutes($router): void
    {
        require __DIR__.'/../workbench/routes/web.php';
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);
        $app['config']->set('session.driver', 'array');
        $app['config']->set('auth.guards.web.driver', 'session');
        $app['config']->set('auth.providers.users.model', \Workbench\App\Models\User::class);
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        $app['config']->set('app.cipher', 'AES-256-GCM');
    }
}


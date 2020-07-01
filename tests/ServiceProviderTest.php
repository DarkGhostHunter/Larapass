<?php

namespace Tests;

use Orchestra\Testbench\TestCase;
use Illuminate\Support\Facades\File;
use DarkGhostHunter\Larapass\LarapassServiceProvider;
use DarkGhostHunter\Larapass\Auth\EloquentWebAuthnProvider;

class ServiceProviderTest extends TestCase
{
    protected function setUp() : void
    {
        $this->afterApplicationCreated([$this, 'cleanFiles']);

        parent::setUp();
    }

    protected function cleanFiles()
    {
        File::deleteDirectory(app_path(), true);
        File::deleteDirectory(database_path('migrations'), true);
        File::delete(base_path('config/larapass.php'));
    }

    public function test_publishes_controllers()
    {
        $this->app->register(LarapassServiceProvider::class);

        $this->artisan('vendor:publish', [
            '--provider' => LarapassServiceProvider::class,
            '--tag'      => 'controllers',
        ])->run();

        $this->assertFileExists(app_path('Http/Controllers/Auth/WebAuthnRegisterController.php'));
        $this->assertFileExists(app_path('Http/Controllers/Auth/WebAuthnLoginController.php'));
    }

    public function test_publishes_config()
    {
        $this->app->register(LarapassServiceProvider::class);

        $this->artisan('vendor:publish', [
            '--provider' => LarapassServiceProvider::class,
            '--tag'      => 'config',
        ])->run();

        $this->assertFileExists(base_path('config/larapass.php'));
    }

    public function test_registers_user_provider()
    {
        $this->app->register(LarapassServiceProvider::class);
        $this->app['config']->set('auth.providers.users.driver', 'eloquent-webauthn');

        $provider = $this->app['auth']->createUserProvider('users');

        $this->assertInstanceOf(EloquentWebAuthnProvider::class, $provider);
    }

    protected function tearDown() : void
    {
        $this->cleanFiles();

        parent::tearDown();
    }
}
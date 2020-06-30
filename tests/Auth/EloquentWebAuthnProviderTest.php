<?php

namespace Tests\Auth;

use Tests\RegistersPackage;
use Illuminate\Support\Str;
use Tests\Stubs\TestWebAuthnUser;
use Orchestra\Testbench\TestCase;
use Illuminate\Support\Facades\DB;
use Tests\RunsPublishableMigrations;
use Illuminate\Support\Facades\Auth;
use Webauthn\TrustPath\EmptyTrustPath;

class EloquentWebAuthnProviderTest extends TestCase
{
    use RegistersPackage,
        RunsPublishableMigrations;

    protected function setUp() : void
    {
        $this->afterApplicationCreated(function () {
            $this->loadLaravelMigrations();
            $this->loadMigrationsFrom([
                '--realpath' => true,
                '--path'     => [
                    realpath(__DIR__ . '/../../database/migrations'),
                ],
            ]);

            $this->app['config']->set('auth.providers.users.driver', 'eloquent-webauthn');
            $this->app['config']->set('auth.providers.users.model', TestWebAuthnUser::class);

        });

        parent::setUp();
    }

    public function test_retrieves_user_using_credential_id()
    {
        $user = TestWebAuthnUser::make()->forceFill([
            'name'     => 'john',
            'email'    => 'john.doe@mail.com',
            'password' => '$2y$10$FLIykVJWDsYSVMJyaFZZfe4tF5uBTnGsosJBL.ZfAAHsYgc27FSdi',
        ]);

        $user->save();

        DB::table('web_authn_credentials')->insert([
            'credential_id'         => 'test_credential_id',
            'user_id'               => 1,
            'is_enabled'            => true,
            'type'                  => 'public_key',
            'transports'            => json_encode([]),
            'attestation_type'      => 'none',
            'trust_path'            => json_encode(['type' => EmptyTrustPath::class]),
            'aaguid'                => Str::uuid()->toString(),
            'credential_public_key' => 'public_key',
            'counter'               => 0,
            'user_handle'           => 'test_user_handle',
            'created_at'            => now()->toDateTimeString(),
            'updated_at'            => now()->toDateTimeString(),
        ]);

        $retrieved = Auth::createUserProvider('users')
            ->retrieveByCredentials([
                'id' => 'test_credential_id',
                'rawId' => 'something',
                'response' => ['something'],
                'type' => 'public-key'
            ]);

        $this->assertTrue($user->is($retrieved));
    }

    public function test_retrieves_user_using_classic_credentials()
    {
        $user = TestWebAuthnUser::make()->forceFill([
            'name'     => 'john',
            'email'    => 'john.doe@mail.com',
            'password' => '$2y$10$FLIykVJWDsYSVMJyaFZZfe4tF5uBTnGsosJBL.ZfAAHsYgc27FSdi',
        ]);

        $user->save();

        $retrieved = Auth::createUserProvider('users')
            ->retrieveByCredentials([
                'email' => 'john.doe@mail.com'
            ]);

        $this->assertTrue($user->is($retrieved));
    }

    public function test_fails_retrieving_user_using_classic_credentials_without_fallback()
    {
        $this->app['config']->set('larapass.fallback', false);

        $user = TestWebAuthnUser::make()->forceFill([
            'name'     => 'john',
            'email'    => 'john.doe@mail.com',
            'password' => '$2y$10$FLIykVJWDsYSVMJyaFZZfe4tF5uBTnGsosJBL.ZfAAHsYgc27FSdi',
        ]);

        $user->save();

        $retrieved = Auth::createUserProvider('users')
            ->retrieveByCredentials([
                'email' => 'john.doe@mail.com'
            ]);

        $this->assertNull($retrieved);
    }

    public function test_validates_user_using_password_fallback()
    {
        $user = TestWebAuthnUser::make()->forceFill([
            'name'     => 'john',
            'email'    => 'john.doe@mail.com',
            'password' => '$2y$10$FLIykVJWDsYSVMJyaFZZfe4tF5uBTnGsosJBL.ZfAAHsYgc27FSdi',
        ]);

        $user->save();

        $result = Auth::createUserProvider('users')
            ->validateCredentials($user, [
                'name' => 'john',
                'password' => 'secret'
            ]);

        $this->assertTrue($result);
    }

    public function test_fails_using_password_and_fallback_disabled()
    {
        $this->app['config']->set('larapass.fallback', false);

        $user = TestWebAuthnUser::make()->forceFill([
            'name'     => 'john',
            'email'    => 'john.doe@mail.com',
            'password' => '$2y$10$FLIykVJWDsYSVMJyaFZZfe4tF5uBTnGsosJBL.ZfAAHsYgc27FSdi',
        ]);

        $user->save();

        $result = Auth::createUserProvider('users')
            ->validateCredentials($user, [
                'name' => 'john',
                'password' => 'secret'
            ]);

        $this->assertFalse($result);
    }
}
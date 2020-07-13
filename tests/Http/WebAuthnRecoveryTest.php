<?php

namespace Tests\Http;

use Mockery;
use Ramsey\Uuid\Uuid;
use Base64Url\Base64Url;
use Tests\RegistersPackage;
use Orchestra\Testbench\TestCase;
use Tests\Stubs\TestWebAuthnUser;
use Illuminate\Support\Facades\DB;
use Tests\RunsPublishableMigrations;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Date;
use Webauthn\TrustPath\EmptyTrustPath;
use Webauthn\PublicKeyCredentialSource;
use DarkGhostHunter\Larapass\WebAuthn\WebAuthnAttestValidator;

class WebAuthnRecoveryTest extends TestCase
{

    use RegistersPackage;
    use RunsPublishableMigrations;

    protected function cleanFiles()
    {
        File::deleteDirectory(app_path(), true);
        File::deleteDirectory(database_path('migrations'));
        File::delete(base_path('config/larapass.php'));
    }

    protected function setUp() : void
    {
        $this->afterApplicationCreated(function () {
            $this->afterApplicationCreated([$this, 'cleanFiles']);
            $this->loadLaravelMigrations();
            $this->loadMigrationsFrom([
                '--realpath' => true,
                '--path'     => [
                    realpath(__DIR__ . '/../../database/migrations'),
                ],
            ]);

            TestWebAuthnUser::make()->forceFill([
                'name'     => 'john',
                'email'    => 'john.doe@mail.com',
                'password' => '$2y$10$FLIykVJWDsYSVMJyaFZZfe4tF5uBTnGsosJBL.ZfAAHsYgc27FSdi',
            ])->save();

            DB::table('web_authn_credentials')->insert([
                'id'               => 'test_credential_foo',
                'user_id'          => 1,
                'type'             => 'public_key',
                'transports'       => json_encode([]),
                'attestation_type' => 'none',
                'trust_path'       => json_encode(['type' => EmptyTrustPath::class]),
                'aaguid'           => '00000000-0000-0000-0000-000000000000',
                'public_key'       => 'public_key',
                'counter'          => 0,
                'user_handle'      => 'test_user_handle',
                'created_at'       => now()->toDateTimeString(),
                'updated_at'       => now()->toDateTimeString(),
                'disabled_at'      => null,
            ]);

            $this->app['config']->set('auth.providers.users.driver', 'eloquent-webauthn');
            $this->app['config']->set('auth.providers.users.model', TestWebAuthnUser::class);
            $this->app['config']->set('auth.passwords.webauthn', [
                'provider' => 'users',
                'table'    => 'web_authn_recoveries',
                'expire'   => 60,
                'throttle' => 60,
            ]);

            require_once __DIR__ . '/../Stubs/Controller.php';
            require_once __DIR__ . '/../Stubs/TestWebAuthnDeviceLostController.php';
            require_once __DIR__ . '/../Stubs/TestWebAuthnRecoveryController.php';

            $this->app['router']
                ->get(
                    'webauthn/lost',
                    'App\Http\Controllers\Auth\TestWebAuthnDeviceLostController@showDeviceLostForm')
                ->name('webauthn.lost.form')
                ->middleware('web');

            $this->app['router']
                ->get(
                    'webauthn/recover',
                    'App\Http\Controllers\Auth\TestWebAuthnRecoveryController@showResetForm')
                ->name('webauthn.recover.form')
                ->middleware('web');
            $this->app['router']
                ->post(
                    'webauthn/recover/options',
                    'App\Http\Controllers\Auth\TestWebAuthnRecoveryController@options')
                ->name('webauthn.recover.options')
                ->middleware('web');
            $this->app['router']
                ->post(
                    'webauthn/recover/register',
                    'App\Http\Controllers\Auth\TestWebAuthnRecoveryController@recover')
                ->name('webauthn.recover')
                ->middleware('web');
        });

        parent::setUp();
    }

    public function test_shows_form()
    {
        $this->get('webauthn/recover?email=john.doe@mail.com&token=test_token')
            ->assertViewIs('larapass::recover')
            ->assertSee(trans('larapass::recovery.instructions'))
            ->assertSee(trans('larapass::recovery.unique'))
            ->assertOk();
    }

    public function test_redirects_when_no_email_or_token_is_present()
    {
        $this->get('webauthn/recover')
            ->assertRedirect(route('webauthn.lost.form'));

        $this->get('webauthn/recover?email=foo@bar.com')
            ->assertRedirect(route('webauthn.lost.form'));

        $this->get('webauthn/recover?token=test_token')
            ->assertRedirect(route('webauthn.lost.form'));
    }

    public function test_requests_attestation_for_new_device()
    {
        Date::setTestNow($now = Date::create(2020, 01, 01, 16, 30));

        DB::table('web_authn_recoveries')->insert([
            'email'      => 'john.doe@mail.com',
            'token'      => '$2y$10$hgGTVVTRLsSYSlAHpyydBu6m4ZuRheBqTTUfRE/aG89DaqEyo.HPu',
            'created_at' => $now->toDateTimeString(),
        ]);

        $this->postJson('webauthn/recover/options', [
            'email' => 'john.doe@mail.com',
            'token' => 'test_token',
        ])->assertJsonStructure([
            'rp',
            'pubKeyCredParams',
            'challenge',
            'attestation',
            'user',
            'authenticatorSelection',
            'timeout',
        ])->assertJsonFragment([
            'user' => [
                'name'        => 'john.doe@mail.com',
                'id'          => base64_encode('test_user_handle'),
                'displayName' => 'john',
            ],
        ]);

        $this->assertDatabaseHas('web_authn_recoveries', [
            'email' => 'john.doe@mail.com',
        ]);
    }

    public function test_fails_if_no_recovery_is_set()
    {
        $this->post('webauthn/recover/options', [
            'email' => 'john.doe@mail.com',
            'token' => 'test_token',
        ])->assertStatus(401);
    }

    public function test_fails_when_token_doesnt_exists()
    {
        DB::table('web_authn_recoveries')->insert([
            'email'      => 'john.doe@mail.com',
            'token'      => '$2y$10$hgGTVVTRLsSYSlAHpyydBu6m4ZuRheBqTTUfRE/aG89DaqEyo.HPu',
            'created_at' => now()->toDateTimeString(),
        ]);

        $this->postJson('webauthn/recover/options', [
            'email' => 'john.doe@mail.com',
            'token' => 'foo_bar',
        ])->assertStatus(401);
    }

    public function test_fails_when_token_expired()
    {
        Date::setTestNow($now = Date::create(2020, 01, 01, 16, 30));

        DB::table('web_authn_recoveries')->insert([
            'email'      => 'john.doe@mail.com',
            'token'      => '$2y$10$hgGTVVTRLsSYSlAHpyydBu6m4ZuRheBqTTUfRE/aG89DaqEyo.HPu',
            'created_at' => $now->clone()->subHour()->subSecond()->toDateTimeString(),
        ]);

        $this->postJson('webauthn/recover/options', [
            'email' => 'john.doe@mail.com',
            'token' => 'test_token',
        ])->assertStatus(401);
    }

    public function test_fails_when_no_user_exists()
    {
        DB::table('web_authn_recoveries')->insert([
            'email'      => 'john.doe@mail.com',
            'token'      => '$2y$10$hgGTVVTRLsSYSlAHpyydBu6m4ZuRheBqTTUfRE/aG89DaqEyo.HPu',
            'created_at' => now()->toDateTimeString(),
        ]);

        $this->postJson('webauthn/recover/options', [
            'email' => 'mike.doe@mail.com',
            'token' => 'test_token',
        ])->assertStatus(401);
    }

    public function test_register_new_device()
    {
        DB::table('web_authn_recoveries')->insert([
            'email'      => 'john.doe@mail.com',
            'token'      => '$2y$10$hgGTVVTRLsSYSlAHpyydBu6m4ZuRheBqTTUfRE/aG89DaqEyo.HPu',
            'created_at' => now()->toDateTimeString(),
        ]);

        $this->mock(WebAuthnAttestValidator::class)
            ->shouldReceive('validate')
            ->with($data = [
                'id'       => 'test_id',
                'rawId'    => Base64Url::encode('test_user_handle'),
                'response' => [
                    'attestationObject' => 'test_attestationObject',
                    'clientDataJSON'    => 'test_clientDataJSON',
                ],
                'type'     => 'test_type',
            ], Mockery::type(TestWebAuthnUser::class))
            ->andReturn(new PublicKeyCredentialSource(
                'test_id',
                'test_type',
                [],
                'none',
                new EmptyTrustPath(),
                Uuid::uuid4(),
                'test_public_key',
                'test_user_handle',
                0
            ));

        $this->postJson('webauthn/recover/register', $data, [
            'email' => 'john.doe@mail.com',
            'token' => 'test_token',
        ])
            ->assertOk()
            ->assertJson([
                'redirectTo' => '/home',
            ]);

        $this->assertDatabaseMissing('web_authn_recoveries', [
            'email' => 'john.doe@mail.com',
        ]);

        $this->assertDatabaseHas('web_authn_credentials', [
            'id' => 'test_id',
        ]);
    }

    public function test_register_new_credential_and_disables_the_rest()
    {
        Date::setTestNow($now = Date::create(2020, 01, 01, 16, 30));

        DB::table('web_authn_recoveries')->insert([
            'email'      => 'john.doe@mail.com',
            'token'      => '$2y$10$hgGTVVTRLsSYSlAHpyydBu6m4ZuRheBqTTUfRE/aG89DaqEyo.HPu',
            'created_at' => now()->toDateTimeString(),
        ]);

        $this->mock(WebAuthnAttestValidator::class)
            ->shouldReceive('validate')
            ->with($data = [
                'id'       => 'test_id',
                'rawId'    => Base64Url::encode('test_user_handle'),
                'response' => [
                    'attestationObject' => 'test_attestationObject',
                    'clientDataJSON'    => 'test_clientDataJSON',
                ],
                'type'     => 'test_type',
            ], Mockery::type(TestWebAuthnUser::class))
            ->andReturn(new PublicKeyCredentialSource(
                'test_id',
                'test_type',
                [],
                'none',
                new EmptyTrustPath(),
                Uuid::uuid4(),
                'test_public_key',
                'test_user_handle',
                0
            ));

        $this->postJson('webauthn/recover/register', $data, [
            'email'           => 'john.doe@mail.com',
            'token'           => 'test_token',
            'WebAuthn-Unique' => 'on',
        ])
            ->assertOk()
            ->assertJson([
                'redirectTo' => '/home',
            ]);

        $this->assertDatabaseMissing('web_authn_recoveries', [
            'email' => 'john.doe@mail.com',
        ]);

        $this->assertDatabaseHas('web_authn_credentials', [
            'id'          => 'test_credential_foo',
            'disabled_at' => $now->toDateTimeString(),
        ]);

        $this->assertDatabaseHas('web_authn_credentials', [
            'id' => 'test_id',
        ]);
    }

    public function test_register_fails_if_no_email_or_token_sent()
    {
        $data = [
            'id'       => 'test_id',
            'rawId'    => Base64Url::encode('test_user_handle'),
            'response' => [
                'attestationObject' => 'test_attestationObject',
                'clientDataJSON'    => 'test_clientDataJSON',
            ],
            'type'     => 'test_type',
        ];

        DB::table('web_authn_recoveries')->insert([
            'email'      => 'john.doe@mail.com',
            'token'      => '$2y$10$hgGTVVTRLsSYSlAHpyydBu6m4ZuRheBqTTUfRE/aG89DaqEyo.HPu',
            'created_at' => now()->toDateTimeString(),
        ]);

        $this->postJson('webauthn/recover/register', $data, [
            'WebAuthn-Unique' => 'on',
        ])->assertStatus(422);

        $this->postJson('webauthn/recover/register', $data, [
            'email'           => 'john.doe@mail.com',
            'WebAuthn-Unique' => 'on',
        ])->assertStatus(422);

        $this->postJson('webauthn/recover/register', $data, [
            'token'           => 'test_token',
            'WebAuthn-Unique' => 'on',
        ])->assertStatus(422);
    }

    public function test_register_fails_if_token_invalid()
    {
        $data = [
            'id'       => 'test_id',
            'rawId'    => Base64Url::encode('test_user_handle'),
            'response' => [
                'attestationObject' => 'test_attestationObject',
                'clientDataJSON'    => 'test_clientDataJSON',
            ],
            'type'     => 'test_type',
        ];

        DB::table('web_authn_recoveries')->insert([
            'email'      => 'john.doe@mail.com',
            'token'      => '$2y$10$hgGTVVTRLsSYSlAHpyydBu6m4ZuRheBqTTUfRE/aG89DaqEyo.HPu',
            'created_at' => now()->toDateTimeString(),
        ]);

        $this->postJson('webauthn/recover/register', $data, [
            'email'           => 'john.doe@mail.com',
            'token'           => 'invalid_token',
            'WebAuthn-Unique' => 'on',
        ])->assertStatus(422);
    }

    public function test_register_fails_when_token_expired()
    {
        Date::setTestNow($now = Date::create(2020, 01, 01, 16, 30));

        $data = [
            'id'       => 'test_id',
            'rawId'    => Base64Url::encode('test_user_handle'),
            'response' => [
                'attestationObject' => 'test_attestationObject',
                'clientDataJSON'    => 'test_clientDataJSON',
            ],
            'type'     => 'test_type',
        ];

        DB::table('web_authn_recoveries')->insert([
            'email'      => 'john.doe@mail.com',
            'token'      => '$2y$10$hgGTVVTRLsSYSlAHpyydBu6m4ZuRheBqTTUfRE/aG89DaqEyo.HPu',
            'created_at' => $now->clone()->subHour()->subSecond()->toDateTimeString(),
        ]);

        $this->postJson('webauthn/recover/register', $data, [
            'email'           => 'john.doe@mail.com',
            'token'           => 'test_token',
            'WebAuthn-Unique' => 'on',
        ])->assertStatus(422);
    }

    public function test_attestation_fails_and_recovery_is_not_deleted()
    {
        DB::table('web_authn_recoveries')->insert([
            'email'      => 'john.doe@mail.com',
            'token'      => '$2y$10$hgGTVVTRLsSYSlAHpyydBu6m4ZuRheBqTTUfRE/aG89DaqEyo.HPu',
            'created_at' => now()->toDateTimeString(),
        ]);

        $this->mock(WebAuthnAttestValidator::class)
            ->shouldReceive('validate')
            ->with($data = [
                'id'       => 'test_id',
                'rawId'    => Base64Url::encode('test_user_handle'),
                'response' => [
                    'attestationObject' => 'test_attestationObject',
                    'clientDataJSON'    => 'test_clientDataJSON',
                ],
                'type'     => 'test_type',
            ], Mockery::type(TestWebAuthnUser::class))
            ->andReturnFalse();

        $this->postJson('webauthn/recover/register', $data, [
            'email'           => 'john.doe@mail.com',
            'token'           => 'test_token',
            'WebAuthn-Unique' => 'true',
        ])
            ->assertStatus(422);

        $this->assertDatabaseHas('web_authn_recoveries', [
            'email' => 'john.doe@mail.com',
        ]);

        $this->assertDatabaseMissing('web_authn_credentials', [
            'id' => 'test_id',
        ]);
    }
}
<?php

namespace Tests\Http;

use Base64Url\Base64Url;
use DarkGhostHunter\Larapass\Eloquent\WebAuthnCredential;
use DarkGhostHunter\Larapass\WebAuthn\WebAuthnAssertValidator;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;
use Orchestra\Testbench\TestCase;
use Tests\RegistersPackage;
use Tests\RunsPublishableMigrations;
use Tests\Stubs\TestWebAuthnUser;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\TrustPath\EmptyTrustPath;

class WebAuthnLoginTest extends TestCase
{
    use RegistersPackage,
        RunsPublishableMigrations;

    protected function cleanFiles()
    {
        File::deleteDirectory(app_path(), true);
        File::deleteDirectory(database_path('migrations'));
        File::delete(base_path('config/larapass.php'));
    }

    protected function setUp() : void
    {
        $this->afterApplicationCreated([$this, 'cleanFiles']);
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

            $this->app['router']->post('webauthn/register/options')
                ->uses('Tests\Stubs\TestWebAuthnRegisterController@options')
                ->name('webauthn.register.options')
                ->middleware('web');
            $this->app['router']->post('webauthn/register')
                ->uses('Tests\Stubs\TestWebAuthnRegisterController@register')
                ->name('webauthn.register')
                ->middleware('web');

            $this->app['router']->post('webauthn/login/options')
                ->uses('Tests\Stubs\TestWebAuthnLoginController@options')
                ->name('webauthn.login.options')
                ->middleware('web');
            $this->app['router']->post('webauthn/login')
                ->uses('Tests\Stubs\TestWebAuthnLoginController@login')
                ->name('webauthn.login')
                ->middleware('web');
        });

        parent::setUp();
    }

    public function test_returns_webauthn_options_for_userless()
    {
        $options = new PublicKeyCredentialRequestOptions(
            $challenge = random_bytes(16),
            60000
        );
        $options->setRpId('test_id')->allowCredentials([])->setUserVerification($options::USER_VERIFICATION_REQUIREMENT_REQUIRED);

        $this->mock(WebAuthnAssertValidator::class)
            ->shouldReceive('generateAssertion')
            ->with(null)
            ->andReturn($options);

        $this->post('webauthn/login/options')->assertExactJson([
            'challenge'        => Base64Url::encode($challenge),
            'rpId'             => 'test_id',
            'userVerification' => 'required',
            'timeout'          => 60000,
        ]);
    }

    public function test_receives_webauthn_options_by_credentials()
    {
        $uuid = Str::uuid();

        TestWebAuthnUser::make()->forceFill([
            'name'     => 'john',
            'email'    => 'john.doe@mail.com',
            'password' => '$2y$10$FLIykVJWDsYSVMJyaFZZfe4tF5uBTnGsosJBL.ZfAAHsYgc27FSdi',
        ])->save();

        DB::table('web_authn_credentials')->insert([
            'id'               => 'dGVzdF9jcmVkZW50aWFsX2lk',
            'user_id'          => 1,
            'type'             => 'public_key',
            'transports'       => json_encode([]),
            'attestation_type' => 'none',
            'trust_path'       => json_encode(['type' => EmptyTrustPath::class]),
            'aaguid'           => $uuid->toString(),
            'public_key'       => 'public_key',
            'counter'          => 0,
            'user_handle'      => 'test_user_handle',
            'created_at'       => now()->toDateTimeString(),
            'updated_at'       => now()->toDateTimeString(),
        ]);

        $this->post('webauthn/login/options', [
            'email' => 'john.doe@mail.com',
        ])
            ->assertJsonStructure([
                'challenge',
                'allowCredentials' => [
                    0 => ['type', 'id'],
                ],
                'timeout',
            ])
            ->assertJson([
                'allowCredentials' => [
                    [
                        'type' => 'public_key',
                        'id'   => 'dGVzdF9jcmVkZW50aWFsX2lk',
                    ],
                ],
            ]);
    }

    public function test_disabled_credential_doesnt_show()
    {
        $uuid = Str::uuid();

        TestWebAuthnUser::make()->forceFill([
            'name'     => 'john',
            'email'    => 'john.doe@mail.com',
            'password' => '$2y$10$FLIykVJWDsYSVMJyaFZZfe4tF5uBTnGsosJBL.ZfAAHsYgc27FSdi',
        ])->save();

        DB::table('web_authn_credentials')->insert([
            'id'               => 'test_credential_id',
            'user_id'          => 1,
            'type'             => 'public_key',
            'transports'       => json_encode([]),
            'attestation_type' => 'none',
            'trust_path'       => json_encode(['type' => EmptyTrustPath::class]),
            'aaguid'           => $uuid->toString(),
            'public_key'       => 'public_key',
            'counter'          => 0,
            'user_handle'      => 'test_user_handle',
            'created_at'       => now()->toDateTimeString(),
            'updated_at'       => now()->toDateTimeString(),
        ]);

        $this->post('webauthn/login/options', [
            'email' => 'john.doe@mail.com',
        ])
            ->assertJsonStructure([
                'challenge',
                'timeout',
            ]);
    }

    public function test_unauthenticated_when_attest_response_is_invalid()
    {
        $this->postJson('webauthn/login', [
            'rawId'    => 'a04f39f8ba6a4a19b98a0579bf76505ea6d55730745274616166ef827b649506',
            'id'       => 'oE85-LpqShm5igV5v3ZQXqbVVzB0UnRhYWbvgntklQY',
            'response' => [
                'authenticatorData' => 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAALQ',
                'signature'         => 'MEUCIQCFOqnsAFZLQmcPt2qSjnCb403SisGEASSjT3fOPuD5JgIgFr1i0_7OR_NiyXU_Usemg9ez8pilwSdQ4QwThlzmHs4',
                'userHandle'        => 'b17b76bc59906cb042d11a3ae33fdced348194084352b52bc8b5de4283b7d035',
                'clientDataJSON'    => 'eyJjaGFsbGVuZ2UiOiJDUXF5aUlrQ00yWEtvaHVSdlNqTEFoNGZfSV9DTkc3SHNPQnZuNWFlOEVZIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9',
            ],
            'type'     => 'public-key',
        ])
            ->assertStatus(422);
    }

    public function test_user_authenticates_with_webauthn()
    {
        $uuid = Str::uuid();

        $user = TestWebAuthnUser::make()->forceFill([
            'name'     => 'john',
            'email'    => 'john.doe@mail.com',
            'password' => '$2y$10$FLIykVJWDsYSVMJyaFZZfe4tF5uBTnGsosJBL.ZfAAHsYgc27FSdi',
        ]);

        $user->save();

        DB::table('web_authn_credentials')->insert([
            'id'               => 'dGVzdF9jcmVkZW50aWFsX2lk',
            'user_id'          => 1,
            'type'             => 'public_key',
            'transports'       => json_encode([]),
            'attestation_type' => 'none',
            'trust_path'       => json_encode(['type' => EmptyTrustPath::class]),
            'aaguid'           => $uuid->toString(),
            'public_key'       => 'public_key',
            'counter'          => 0,
            'user_handle'      => 'test_user_handle',
            'created_at'       => now()->toDateTimeString(),
            'updated_at'       => now()->toDateTimeString(),
        ]);

        $data = [
            'id'       => 'dGVzdF9jcmVkZW50aWFsX2lk',
            'rawId'    => 'ZEdWemRGOWpjbVZrWlc1MGFXRnNYMmxr',
            'type'     => 'test_type',
            'response' => [
                'authenticatorData' => 'test',
                'clientDataJSON' => 'test',
                'signature' => 'test',
                'userHandle' => 'test',
            ],
        ];

        $this->mock(WebAuthnAssertValidator::class)
            ->shouldReceive('validate')
            ->with($data)
            ->andReturnUsing(function ($data) {
                $credentials = WebAuthnCredential::find($data['id']);

                $credentials->setAttribute('counter', 1)->save();

                return $credentials->toCredentialSource();
            });

        $this->postJson('webauthn/login', $data)->assertNoContent();

        $this->assertAuthenticatedAs($user);

        $this->assertDatabaseHas('web_authn_credentials', [
            'id'      => 'dGVzdF9jcmVkZW50aWFsX2lk',
            'counter' => 1,
        ]);
    }

    protected function tearDown() : void
    {
        Str::createUuidsNormally();

        $this->afterApplicationCreated([$this, 'cleanFiles']);

        parent::tearDown();
    }
}

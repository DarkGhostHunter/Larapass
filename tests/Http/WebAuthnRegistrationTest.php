<?php

namespace Tests\Http;

use Ramsey\Uuid\Uuid;
use Base64Url\Base64Url;
use Tests\RegistersPackage;
use Illuminate\Support\Str;
use Orchestra\Testbench\TestCase;
use Tests\Stubs\TestWebAuthnUser;
use Tests\RunsPublishableMigrations;
use Illuminate\Support\Facades\File;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Event;
use Webauthn\TrustPath\EmptyTrustPath;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialCreationOptions;
use DarkGhostHunter\Larapass\Events\AttestationSuccessful;
use DarkGhostHunter\Larapass\WebAuthn\WebAuthnAttestCreator;
use DarkGhostHunter\Larapass\WebAuthn\WebAuthnAttestValidator;

class WebAuthnRegistrationTest extends TestCase
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

    public function test_returns_attestation_options()
    {
        $challenge = new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity('test', 'app.com'),
            new PublicKeyCredentialUserEntity('test_name', 'test_id', 'test_display_name'),
            $bytes = random_bytes(16),
            [new PublicKeyCredentialParameters('public-key', -7)],
            60000,
            [],
            null,
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            null
        );

        $user = TestWebAuthnUser::make()->forceFill([
            'name'     => 'john',
            'email'    => 'john.doe@mail.com',
            'password' => '$2y$10$FLIykVJWDsYSVMJyaFZZfe4tF5uBTnGsosJBL.ZfAAHsYgc27FSdi',
        ]);

        $user->save();

        $this->actingAs($user);

        Str::createUuidsUsing(function () {
            return Uuid::fromString('1c3c674c-2f09-4079-8e57-ddc5fe5e66eb');
        });

        $this->mock(WebAuthnAttestCreator::class)
            ->shouldReceive('generateAttestation')
            ->andReturn($challenge);

        $this->post('webauthn/register/options')->assertExactJson([
            'rp'                     => [
                'id'   => 'app.com',
                'name' => 'test',
            ],
            'pubKeyCredParams'       => [
                ['type' => 'public-key', 'alg' => -7],
            ],
            'challenge'              => Base64Url::encode($bytes),
            'attestation'            => 'none',
            'user'                   => [
                'name'        => 'test_name',
                'id'          => 'dGVzdF9pZA==',
                'displayName' => 'test_display_name',
            ],
            'authenticatorSelection' => [
                'requireResidentKey' => false,
                'userVerification'   => 'preferred',
            ],
            'timeout'                => 60000,
        ])->assertOk();
    }

    public function test_error_if_user_not_web_authn_authenticatable()
    {
        $user = User::make()->forceFill([
            'name'     => 'john',
            'email'    => 'john.doe@mail.com',
            'password' => '$2y$10$FLIykVJWDsYSVMJyaFZZfe4tF5uBTnGsosJBL.ZfAAHsYgc27FSdi',
        ]);

        $user->save();

        $this->actingAs($user);

        $this->post('webauthn/register/options')->assertStatus(500);
    }

    public function test_success_when_checks_assertion()
    {
        $event = Event::fake();

        $user = TestWebAuthnUser::make()->forceFill([
            'name'     => 'john',
            'email'    => 'john.doe@mail.com',
            'password' => '$2y$10$FLIykVJWDsYSVMJyaFZZfe4tF5uBTnGsosJBL.ZfAAHsYgc27FSdi',
        ]);

        $user->save();

        $this->actingAs($user);

        $this->mock(WebAuthnAttestValidator::class)
            ->shouldReceive('validate')
            ->with($data = [
                'id'       => 'test_id',
                'rawId'    => Base64Url::encode('test_id'),
                'response' => [
                    'attestationObject' => 'test',
                    'clientDataJSON'    => 'test',
                ],
                'type'     => 'test_public_key',
            ], $user)
            ->andReturnUsing(function (array $data) {
                return new PublicKeyCredentialSource(
                    $data['rawId'],
                    'test_type',
                    [],
                    'test_attestation',
                    new EmptyTrustPath(),
                    Uuid::fromString('1c3c674c-2f09-4079-8e57-ddc5fe5e66eb'),
                    'test_public_key',
                    'test_user_handle',
                    0
                );
            });

        Date::setTestNow($now = Date::create(2020, 04, 01, 16, 30));

        $this->postJson('webauthn/register', $data)->assertNoContent();

        $this->assertDatabaseHas('web_authn_credentials', [
            'id'               => $data['rawId'],
            'user_id'          => 1,
            'type'             => 'test_type',
            'transports'       => json_encode([]),
            'attestation_type' => 'test_attestation',
            'trust_path'       => json_encode(['type' => EmptyTrustPath::class]),
            'aaguid'           => '1c3c674c-2f09-4079-8e57-ddc5fe5e66eb',
            'counter'          => 0,
            'user_handle'      => 'test_user_handle',
            'created_at'       => $now->toDateTimeString(),
            'updated_at'       => $now->toDateTimeString(),
            'disabled_at'      => null,
            'public_key'       => 'test_public_key',
        ]);

        $event->assertDispatched(AttestationSuccessful::class, function ($event) use ($user, $data) {
            return $user->is($event->user)
                && $data['rawId'] === $event->credential->getPublicKeyCredentialId();
        });
    }

    public function test_uses_resident_key()
    {
        $this->app['config']->set('larapass.userless', 'preferred');

        $user = TestWebAuthnUser::make()->forceFill([
            'name'     => 'john',
            'email'    => 'john.doe@mail.com',
            'password' => '$2y$10$FLIykVJWDsYSVMJyaFZZfe4tF5uBTnGsosJBL.ZfAAHsYgc27FSdi',
        ]);

        $user->save();

        $this->actingAs($user);

        $this->post('webauthn/register/options')
            ->assertJsonFragment([
                'authenticatorSelection' => [
                    'requireResidentKey' => false,
                    'residentKey'        => 'preferred',
                    'userVerification'   => 'preferred',
                ],
            ])->assertStatus(200);
    }

    public function test_exception_on_invalid_resident_key()
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('The invalid as Resident Key option is unsupported.');

        $this->app['config']->set('larapass.userless', 'invalid');

        $user = TestWebAuthnUser::make()->forceFill([
            'name'     => 'john',
            'email'    => 'john.doe@mail.com',
            'password' => '$2y$10$FLIykVJWDsYSVMJyaFZZfe4tF5uBTnGsosJBL.ZfAAHsYgc27FSdi',
        ]);

        $user->save();

        $this->app[WebAuthnAttestCreator::class]->retrieveAttestation($user);
    }

    public function test_fails_assertion()
    {
        $event = Event::fake();

        $user = TestWebAuthnUser::make()->forceFill([
            'name'     => 'john',
            'email'    => 'john.doe@mail.com',
            'password' => '$2y$10$FLIykVJWDsYSVMJyaFZZfe4tF5uBTnGsosJBL.ZfAAHsYgc27FSdi',
        ]);

        $user->save();

        $this->actingAs($user);

        $this->mock(WebAuthnAttestValidator::class)
            ->shouldReceive('validate')
            ->with($data = [
                'id'       => 'WsVEgVplFhLkRd68yW3KAIyVJ90ZsQOHFjnL71YirSY',
                'rawId'    => 'WsVEgVplFhLkRd68yW3KAIyVJ90ZsQOHFjnL71YirSY=',
                'response' => [
                    'clientDataJSON'    => 'ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5jcmVhdGUiLA0KCSJjaGFsbGVuZ2UiIDogIlhLQURrWlNXOUI0aDBGZWs4S2JoUXVuM200ZGZKWU4zY2k5d2RYRE5KdlUiLA0KCSJvcmlnaW4iIDogImh0dHBzOi8vd2ViYXV0aG4uc3BvbWt5LWxhYnMuY29tIiwNCgkidG9rZW5CaW5kaW5nIiA6IA0KCXsNCgkJInN0YXR1cyIgOiAic3VwcG9ydGVkIg0KCX0NCn0',
                    'attestationObject' => 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBZ5YE6oKCTpikraFLRGLQ1zqOxGkTDakbGTB0WSKfdKNZRQAAAABgKLAXsdRMArSzr82vyWuyACBaxUSBWmUWEuRF3rzJbcoAjJUn3RmxA4cWOcvvViKtJqQBAwM5AQAgWQEAv5VUWjpRGBvp2zawiX2JKC9WSDvVxlLfqNqU1EYsdN6iNg16FFF/0EHkt7tJz9wkwC3Cx5vYFyblUw7UF5m8qS579OcGRjvb6MHj+MQFuOKCoowBMY/VjuF+TT14deKMuWtShT2MCab1gtfnkuGAlEcu2CASvAwtbEPKZ2JkaouWWaJ3hDOYTXWYgCgtM5DqqnN9JUZjXrgmAfQC82SYh6ZAV+MQ2s4RG2jP/dvEt235oFSIkr3JEqhStQvJ+CFmjVk67oFtofcISax44CynCd2Lr89inWU1B0JwSB1oyuLPq5HCQuSmFed/piGjVfFgCbN0tCXJkAGufkDXE3J4xSFDAQAB',
                ],
                'type'     => 'public-key',
            ], $user)
            ->andReturnFalse();

        $this->postJson('webauthn/register', $data)->assertNoContent(422);

        $this->assertDatabaseMissing('web_authn_credentials', [
            'id' => 'test_credential_id',
        ]);

        $event->assertNotDispatched(AttestationSuccessful::class);
    }

    protected function tearDown() : void
    {
        Str::createUuidsNormally();

        $this->afterApplicationCreated([$this, 'cleanFiles']);

        parent::tearDown();
    }
}
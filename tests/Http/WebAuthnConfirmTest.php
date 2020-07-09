<?php

namespace Tests\Http;

use Base64Url\Base64Url;
use Tests\RegistersPackage;
use Tests\Stubs\TestWebAuthnUser;
use Orchestra\Testbench\TestCase;
use Illuminate\Support\Facades\DB;
use Tests\RunsPublishableMigrations;
use Illuminate\Support\Facades\File;
use Webauthn\TrustPath\EmptyTrustPath;
use DarkGhostHunter\Larapass\Eloquent\WebAuthnCredential;
use DarkGhostHunter\Larapass\WebAuthn\WebAuthnAssertValidator;

class WebAuthnConfirmTest extends TestCase
{
    use RegistersPackage;
    use RunsPublishableMigrations;

    /** @var \Tests\Stubs\TestWebAuthnUser */
    protected $user;

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

            $this->user = TestWebAuthnUser::make()->forceFill([
                'name'     => 'john',
                'email'    => 'john.doe@mail.com',
                'password' => '$2y$10$FLIykVJWDsYSVMJyaFZZfe4tF5uBTnGsosJBL.ZfAAHsYgc27FSdi',
            ]);

            $this->user->save();

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

            $this->app['router']->get('login', function () {
                return 'please login';
            })
                ->name('login')
                ->middleware('web');

            $this->app['router']->get('webauthn/confirm',
                'Tests\Stubs\TestWebAuthnConfirmController@showConfirmForm')
                ->name('webauthn.confirm.form')->middleware(['web']);
            $this->app['router']->post('webauthn/confirm/options',
                'Tests\Stubs\TestWebAuthnConfirmController@options')
                ->name('webauthn.confirm.options')->middleware(['web']);
            $this->app['router']->post('webauthn/confirm',
                'Tests\Stubs\TestWebAuthnConfirmController@confirm')
                ->name('webauthn.confirm')->middleware(['web']);

            $this->app['router']->get('intended', function () {
                return 'ok';
            })->middleware('webauthn.confirm', 'web');
        });

        parent::setUp();
    }

    public function test_asks_for_confirmation()
    {
        $this->actingAs($this->user)
            ->get('intended')
            ->assertRedirect('webauthn/confirm');

        $this->actingAs($this->user)
            ->followingRedirects()
            ->get('intended')
            ->dump()
            ->assertViewIs('larapass::confirm')
            ->assertOk();
    }

    public function test_receives_attestation_options()
    {
        $this->postJson('webauthn/confirm/options')
            ->assertUnauthorized();

        $this->actingAs($this->user)
            ->postJson('webauthn/confirm/options')
            ->assertJsonStructure([
                'challenge',
                'allowCredentials' => [
                    0 => ['type', 'id'],
                ],
                'timeout',
            ]);
    }

    public function test_confirmed_user_gets_intended_route()
    {
        $this->actingAs($this->user)
            ->get('intended')
            ->assertRedirect('webauthn/confirm');

        $this->mock(WebAuthnAssertValidator::class)
            ->shouldReceive('validate')
            ->with($data = [
                'id'       => 'test_credential_foo',
                'rawId'    => Base64Url::encode('test_credential_foo'),
                'type'     => 'test_type',
                'response' => [
                    'authenticatorData' => 'test',
                    'clientDataJSON' => 'test',
                    'signature' => 'test',
                    'userHandle' => 'test',
                ],
            ])
            ->andReturnUsing(function ($data) {
                $credentials = WebAuthnCredential::find($data['id']);

                $credentials->setAttribute('counter', 1)->save();

                return $credentials->toCredentialSource();
            });

        $this
            ->postJson('webauthn/confirm', $data)
            ->assertExactJson([
                'redirectTo' => 'http://localhost/intended'
            ]);

        $this
            ->get('intended', $data)
            ->assertSee('ok');
    }

    public function test_returns_error_if_validation_fails()
    {
        $this->actingAs($this->user)
            ->get('intended')
            ->assertRedirect('webauthn/confirm');

        $this->postJson('webauthn/confirm', [
                'foo' => 'bar'
            ])
            ->assertStatus(422);
    }

    public function test_returns_error_if_attestation_fails()
    {
        $this->actingAs($this->user)
            ->get('intended')
            ->assertRedirect('webauthn/confirm');

        $this->mock(WebAuthnAssertValidator::class)
            ->shouldReceive('validate')
            ->with($data = [
                'id'       => 'test_credential_foo',
                'rawId'    => Base64Url::encode('test_credential_foo'),
                'type'     => 'test_type',
                'response' => [
                    'authenticatorData' => 'test',
                    'clientDataJSON' => 'test',
                    'signature' => 'test',
                    'userHandle' => 'test',
                ],
            ])
            ->andReturnFalse();

        $this
            ->postJson('webauthn/confirm', $data)
            ->assertStatus(422);
    }
}
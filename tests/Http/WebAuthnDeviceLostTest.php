<?php

namespace Tests\Http;

use DarkGhostHunter\Larapass\Notifications\AccountRecoveryNotification;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Notification;
use Orchestra\Testbench\TestCase;
use Tests\RegistersPackage;
use Tests\RunsPublishableMigrations;
use Tests\Stubs\TestWebAuthnUser;
use Webauthn\TrustPath\EmptyTrustPath;

class WebAuthnDeviceLostTest extends TestCase
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
                'disabled_at'       => null,
            ]);

            $this->app['config']->set('auth.providers.users.driver', 'eloquent-webauthn');
            $this->app['config']->set('auth.providers.users.model', TestWebAuthnUser::class);
            $this->app['config']->set('auth.passwords.webauthn' , [
                'provider' => 'users',
                'table' => 'web_authn_recoveries',
                'expire' => 60,
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
                ->post(
                    'webauthn/lost',
                    'App\Http\Controllers\Auth\TestWebAuthnDeviceLostController@sendRecoveryEmail')
                ->name('webauthn.lost.send')
                ->middleware('web');

            $this->app['router']
                ->get(
                    'webauthn/recover',
                    'App\Http\Controllers\Auth\TestWebAuthnRecoveryController@showResetForm')
                ->name('webauthn.recover.form')
                ->middleware('web');
        });

        parent::setUp();
    }

    public function test_shows_recovery_form()
    {
        $this->get('webauthn/lost')
            ->assertViewIs('larapass::lost')
            ->assertSee(trans('larapass::recovery.title'))
            ->assertSee(trans('larapass::recovery.description'))
            ->assertSee(trans('larapass::recovery.button.send'))
            ->assertSee(route('webauthn.lost.send'));
    }

    public function test_sends_recovery_email()
    {
        $notification = Notification::fake();

        $this->post('webauthn/lost', [
            'email' => 'john.doe@mail.com'
        ], [
            'HTTP_REFERER' => route('webauthn.lost.form')
        ])
            ->assertSessionHas('status')
            ->assertRedirect(route('webauthn.lost.form'));

        $notification->assertSentTo(TestWebAuthnUser::first(), AccountRecoveryNotification::class);

        $this->assertDatabaseHas('web_authn_recoveries', [
            'email' => 'john.doe@mail.com'
        ]);
    }

    public function test_sends_recovery_email_using_json()
    {
        $notification = Notification::fake();

        $this->postJson('webauthn/lost', [
            'email' => 'john.doe@mail.com'
        ])
            ->assertSeeText(trans('larapass::recovery.sent'));

        $notification->assertSentTo(TestWebAuthnUser::first(), AccountRecoveryNotification::class);

        $this->assertDatabaseHas('web_authn_recoveries', [
            'email' => 'john.doe@mail.com'
        ]);
    }

    public function test_error_if_email_invalid()
    {
        $notification = Notification::fake();

        $this->post('webauthn/lost', [
            'email' => 'invalid'
        ], [
            'HTTP_REFERER' => route('webauthn.lost.form')
        ])
            ->assertRedirect(route('webauthn.lost.form'))
            ->assertSessionHasErrors(['email']);

        $this->postJson('webauthn/lost', [
            'email' => 'invalid'
        ])
            ->assertSeeText('The given data was invalid');

        $notification->assertNothingSent();

        $this->assertDatabaseMissing('web_authn_recoveries', [
            'email' => 'john.doe@mail.com'
        ]);
    }

    public function test_error_if_user_email_doesnt_exists()
    {
        $notification = Notification::fake();

        $this->post('webauthn/lost', [
            'email' => 'foo@bar.com'
        ], [
            'HTTP_REFERER' => route('webauthn.lost.form')
        ])
            ->assertRedirect(route('webauthn.lost.form'))
            ->assertSessionHasErrors(['email']);

        $this->postJson('webauthn/lost', [
            'email' => 'foo@bar.com'
        ])
            ->assertSeeText('The given data was invalid');

        $notification->assertNothingSent();

        $this->assertDatabaseMissing('web_authn_recoveries', [
            'email' => 'john.doe@mail.com'
        ]);
    }

    public function test_throttled_on_resend()
    {
        $notification = Notification::fake();

        Date::setTestNow($now = Date::create(2020, 01, 01, 16, 30));

        $this->post('webauthn/lost', [
            'email' => 'john.doe@mail.com'
        ], [
            'HTTP_REFERER' => route('webauthn.lost.form')
        ])
            ->assertSessionHas('status')
            ->assertRedirect(route('webauthn.lost.form'));

        $notification->assertSentTo(TestWebAuthnUser::first(), AccountRecoveryNotification::class);

        $this->assertDatabaseHas('web_authn_recoveries', [
            'email' => 'john.doe@mail.com'
        ]);

        $this->post('webauthn/lost', [
            'email' => 'john.doe@mail.com'
        ], [
            'HTTP_REFERER' => route('webauthn.lost.form')
        ])
            ->assertRedirect(route('webauthn.lost.form'))
            ->assertSessionHasErrors(['email']);

        $this->postJson('webauthn/lost', [
            'email' => 'john.doe@mail.com'
        ])
            ->assertSeeText(trans('larapass::recovery.throttled'));
    }

    public function test_error_if_no_broker_is_set()
    {
        $this->app['config']->set('auth.passwords.webauthn', null);

        $this->post('webauthn/lost', [
            'email' => 'john.doe@mail.com'
        ], [
            'HTTP_REFERER' => route('webauthn.lost.form')
        ])
            ->assertStatus(500);
    }
}

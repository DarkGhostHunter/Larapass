<?php

namespace Tests\Notifications;

use Orchestra\Testbench\TestCase;
use Tests\Stubs\TestWebAuthnUser;
use DarkGhostHunter\Larapass\Notifications\AccountRecoveryNotification;

class AccountRecoveryNotificationTest extends TestCase
{
    public function test_notifications_renders_to_email()
    {
        $this->app['config']->set('auth.passwords.webauthn', [
            'provider' => 'users',
            'table'    => 'web_authn_recoveries',
            'expire'   => 15,
            'throttle' => 60,
        ]);

        $this->app['router']->get('route', function () {})->name('webauthn.recover.form');

        $user = TestWebAuthnUser::make()->forceFill([
            'email' => 'test@test.com'
        ]);

        $mail = (new AccountRecoveryNotification('test_token'))->toMail($user)->render();

        $this->assertStringContainsString(
            '<a href="http://localhost/route?token=test_token&amp;email=test%40test.com"',
            $mail
        );

        $this->assertStringContainsString(
            'Recover Account</a>',
            $mail
        );

        $this->assertStringContainsString(
            'You are receiving this email because we received an account recovery request for your account',
            $mail
        );

        $this->assertStringContainsString(
            'This recovery link will expire in 15 minutes.',
            $mail
        );

        $this->assertStringContainsString(
            'If you did not request an account recovery, no further action is required.',
            $mail
        );
    }
}
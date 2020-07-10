<?php

namespace DarkGhostHunter\Larapass\Notifications;

use Illuminate\Support\Facades\Lang;
use Illuminate\Notifications\Notification;
use Illuminate\Notifications\Messages\MailMessage;

class AccountRecoveryNotification extends Notification
{
    /**
     * Token for account recovery.
     *
     * @var string
     */
    protected $token;

    /**
     * The callback that should be used to create the reset password URL.
     *
     * @var \Closure|null
     */
    protected static $createUrlCallback;

    /**
     * The callback that should be used to build the mail message.
     *
     * @var \Closure|null
     */
    protected static $toMailCallback;

    /**
     * AccountRecoveryNotification constructor.
     *
     * @param  string  $token
     */
    public function __construct(string $token)
    {
        $this->token = $token;
    }

    /**
     * Get the notification's channels.
     *
     * @param  mixed  $notifiable
     * @return array|string
     */
    public function via($notifiable)
    {
        return ['mail'];
    }

    /**
     * Build the mail representation of the notification.
     *
     * @param  mixed  $notifiable
     * @return \Illuminate\Notifications\Messages\MailMessage
     */
    public function toMail($notifiable)
    {
        if (static::$toMailCallback) {
            return call_user_func(static::$toMailCallback, $notifiable, $this->token);
        }

        if (static::$createUrlCallback) {
            $url = call_user_func(static::$createUrlCallback, $notifiable, $this->token);
        } else {
            $url = url(route('webauthn.recover.form', [
                'token' => $this->token,
                'email' => $notifiable->getEmailForPasswordReset(),
            ], false));
        }

        return (new MailMessage)
            ->subject(Lang::get('Account Recovery Notification'))
            ->line(Lang::get('You are receiving this email because we received an account recovery request for your account.'))
            ->action(Lang::get('Recover Account'), $url)
            ->line(Lang::get('This recovery link will expire in :count minutes.', [
                'count' => config('auth.passwords.webauthn.expire')
            ]))
            ->line(Lang::get('If you did not request an account recovery, no further action is required.'));
    }

    /**
     * Set a callback that should be used when creating the reset password button URL.
     *
     * @param  callable  $callback
     * @return void
     */
    public static function createUrlUsing($callback)
    {
        static::$createUrlCallback = $callback;
    }

    /**
     * Set a callback that should be used when building the notification mail message.
     *
     * @param  callable  $callback
     * @return void
     */
    public static function toMailUsing($callback)
    {
        static::$toMailCallback = $callback;
    }
}
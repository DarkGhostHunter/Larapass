<?php

namespace DarkGhostHunter\Larapass\Auth;

use Closure;
use DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable;
use Illuminate\Auth\Passwords\PasswordBroker;
use Illuminate\Contracts\Auth\CanResetPassword as CanResetPasswordContract;

class CredentialBroker extends PasswordBroker
{
    /**
     * Constant representing a successfully sent reminder.
     *
     * @var string
     */
    public const RESET_LINK_SENT = 'larapass::recovery.sent';

    /**
     * Constant representing a successfully reset password.
     *
     * @var string
     */
    public const PASSWORD_RESET = 'larapass::recovery.reset';

    /**
     * Constant representing the user not found response.
     *
     * @var string
     */
    public const INVALID_USER = 'larapass::recovery.user';

    /**
     * Constant representing an invalid token.
     *
     * @var string
     */
    public const INVALID_TOKEN = 'larapass::recovery.token';

    /**
     * Constant representing a throttled reset attempt.
     *
     * @var string
     */
    public const RESET_THROTTLED = 'larapass::recovery.throttled';

    /**
     * Send a password reset link to a user.
     *
     * @param  array  $credentials
     * @param  \Closure|null  $callback
     *
     * @return string
     */
    public function sendResetLink(array $credentials, Closure $callback = null): string
    {
        $user = $this->getUser($credentials);

        if (!$user instanceof WebAuthnAuthenticatable) {
            return static::INVALID_USER;
        }

        if ($this->tokens->recentlyCreatedToken($user)) {
            return static::RESET_THROTTLED;
        }

        $token = $this->tokens->create($user);

        if ($callback) {
            $callback($user, $token);
        } else {
            $user->sendCredentialRecoveryNotification($token);
        }

        return static::RESET_LINK_SENT;
    }

    /**
     * Reset the password for the given token.
     *
     * @param  array  $credentials
     * @param  \Closure  $callback
     *
     * @return \Illuminate\Contracts\Auth\CanResetPassword|string
     */
    public function reset(array $credentials, Closure $callback)
    {
        $user = $this->validateReset($credentials);

        if (!$user instanceof CanResetPasswordContract || !$user instanceof WebAuthnAuthenticatable) {
            return $user;
        }

        $callback($user);

        $this->tokens->delete($user);

        return static::PASSWORD_RESET;
    }
}

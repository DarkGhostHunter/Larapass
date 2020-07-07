<?php

namespace DarkGhostHunter\Larapass\Auth\Credentials;

use Closure;
use UnexpectedValueException;
use Illuminate\Auth\Passwords\PasswordBroker;
use DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable;
use Illuminate\Contracts\Auth\CanResetPassword as CanResetPasswordContract;

class CredentialBroker extends PasswordBroker
{
    /**
     * Constant representing a successfully sent reminder.
     *
     * @var string
     */
    public const RESET_LINK_SENT = 'credentials.sent';

    /**
     * Constant representing a successfully reset password.
     *
     * @var string
     */
    public const PASSWORD_RESET = 'credentials.reset';

    /**
     * Constant representing the user not found response.
     *
     * @var string
     */
    public const INVALID_USER = 'credentials.user';

    /**
     * Constant representing an invalid token.
     *
     * @var string
     */
    public const INVALID_TOKEN = 'credentials.token';

    /**
     * Constant representing a throttled reset attempt.
     *
     * @var string
     */
    public const RESET_THROTTLED = 'credentials.throttled';

    /**
     * Send a password reset link to a user.
     *
     * @param  array  $credentials
     * @return string
     */
    public function sendResetLink(array $credentials)
    {
        $user = $this->getUser($credentials);

        if (! $user instanceof WebAuthnAuthenticatable) {
            return static::INVALID_USER;
        }

        if ($this->tokens->recentlyCreatedToken($user)) {
            return static::RESET_THROTTLED;
        }

        $user->sendCredentialRecoveryNotification(
            $this->tokens->create($user)
        );

        return static::RESET_LINK_SENT;
    }

    /**
     * Reset the password for the given token.
     *
     * @param  array  $credentials
     * @param  \Closure  $callback
     * @return mixed
     */
    public function reset(array $credentials, Closure $callback)
    {
        $user = $this->validateReset($credentials);

        if (! $user instanceof CanResetPasswordContract || ! $user instanceof WebAuthnAuthenticatable) {
            return $user;
        }

        $callback($user);

        $this->tokens->delete($user);

        return static::PASSWORD_RESET;
    }

    /**
     * Get the user for the given credentials.
     *
     * @param  array  $credentials
     * @return \Illuminate\Contracts\Auth\CanResetPassword|null
     *
     * @throws \UnexpectedValueException
     */
    public function getUser(array $credentials)
    {
        $user = parent::getUser($credentials);

        if ($user && ! $user instanceof WebAuthnAuthenticatable) {
            throw new UnexpectedValueException('User must implement WebAuthnAuthenticatable interface.');
        }

        return $user;
    }
}
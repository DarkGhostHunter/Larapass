<?php

namespace DarkGhostHunter\Larapass\Facades;

use Closure;
use DarkGhostHunter\Larapass\Auth\CredentialBroker;
use DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable;
use DarkGhostHunter\Larapass\WebAuthn\WebAuthnAssertValidator;
use DarkGhostHunter\Larapass\WebAuthn\WebAuthnAttestCreator;
use DarkGhostHunter\Larapass\WebAuthn\WebAuthnAttestValidator;
use Illuminate\Support\Facades\Facade;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;

class WebAuthn extends Facade
{
    /**
     * Constant representing a successfully sent recovery.
     *
     * @var string
     */
    public const RECOVERY_SENT = CredentialBroker::RESET_LINK_SENT;

    /**
     * Constant representing a successfully reset recovery.
     *
     * @var string
     */
    public const RECOVERY_ATTACHED = CredentialBroker::PASSWORD_RESET;

    /**
     * Constant representing the user not found response.
     *
     * @var string
     */
    public const INVALID_USER = CredentialBroker::INVALID_USER;

    /**
     * Constant representing an invalid token.
     *
     * @var string
     */
    public const INVALID_TOKEN = CredentialBroker::INVALID_TOKEN;

    /**
     * Constant representing a throttled reset attempt.
     *
     * @var string
     */
    public const RECOVERY_THROTTLED = CredentialBroker::RESET_THROTTLED;

    /**
     * Creates a new attestation (registration) request.
     *
     * @param  \DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable  $user
     *
     * @return \Webauthn\PublicKeyCredentialCreationOptions
     */
    public static function generateAttestation(WebAuthnAuthenticatable $user): PublicKeyCredentialCreationOptions
    {
        return static::$app[WebAuthnAttestCreator::class]->generateAttestation($user);
    }

    /**
     * Validates the attestation response, and returns the validated credentials.
     *
     * It returns `false` when the validation fails.
     *
     * @param  array  $data
     * @param  \DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable  $user
     *
     * @return bool|\Webauthn\PublicKeyCredentialSource
     */
    public static function validateAttestation(array $data, WebAuthnAuthenticatable $user)
    {
        return static::$app[WebAuthnAttestValidator::class]->validate($data, $user);
    }

    /**
     * Creates a new assertion request for a given user, or blank if there is no user given.
     *
     * @param  \DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable|null  $user
     *
     * @return \Webauthn\PublicKeyCredentialRequestOptions
     */
    public static function generateAssertion(?WebAuthnAuthenticatable $user = null): PublicKeyCredentialRequestOptions
    {
        return static::$app[WebAuthnAssertValidator::class]->generateAssertion($user);
    }

    /**
     * Validates the attestation response, and returns the used credentials.
     *
     * It returns `false` when the validation fails.
     *
     * @param  array  $data
     *
     * @return bool
     */
    public static function validateAssertion(array $data): bool
    {
        return (bool)static::$app[WebAuthnAssertValidator::class]->validate($data);
    }

    /**
     * Sends an account recovery email to an user by the credentials.
     *
     * @param  array  $credentials
     *
     * @return string
     */
    public static function sendRecoveryLink(array $credentials): string
    {
        return static::$app[CredentialBroker::class]->sendResetLink($credentials);
    }

    /**
     * Recover the account for the given token.
     *
     * @param  array  $credentials
     * @param  \Closure  $callback
     *
     * @return \Illuminate\Contracts\Auth\CanResetPassword|mixed|string
     */
    public static function recover(array $credentials, Closure $callback)
    {
        return static::$app[CredentialBroker::class]->reset($credentials, $callback);
    }

    /**
     * Get the user for the given credentials.
     *
     * @param  array  $credentials
     *
     * @return null|\DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable|\Illuminate\Contracts\Auth\CanResetPassword
     */
    public static function getUser(array $credentials)
    {
        return static::$app[CredentialBroker::class]->getUser($credentials);
    }

    /**
     * Validate the given account recovery token.
     *
     * @param  \DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable|\Illuminate\Contracts\Auth\CanResetPassword|null  $user
     * @param  string  $token
     *
     * @return bool
     */
    public static function tokenExists($user, string $token): bool
    {
        return $user ? static::$app[CredentialBroker::class]->tokenExists($user, $token) : false;
    }
}

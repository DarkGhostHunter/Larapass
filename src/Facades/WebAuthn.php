<?php

namespace DarkGhostHunter\Larapass\Facades;

use Illuminate\Support\Facades\Facade;
use DarkGhostHunter\Larapass\WebAuthn\WebAuthnAttestCreator;
use DarkGhostHunter\Larapass\WebAuthn\WebAuthnAttestValidator;
use DarkGhostHunter\Larapass\WebAuthn\WebAuthnAssertValidator;
use DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable;

class WebAuthn extends Facade
{
    /**
     * Creates a new attestation (registration) request.
     *
     * @param  \DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable  $user
     * @return \Webauthn\PublicKeyCredentialCreationOptions
     */
    public static function generateAttestation(WebAuthnAuthenticatable $user)
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
     * @return bool|\Webauthn\PublicKeyCredentialSource
     */
    public static function validateAttestation(array $data, WebAuthnAuthenticatable $user)
    {
        return static::$app[WebAuthnAttestValidator::class]->validate($data, $user);
    }

    /**
     * Creates a new assertion request for a given user.
     *
     * @param  \DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable  $user
     * @return \Webauthn\PublicKeyCredentialRequestOptions
     */
    public static function generateAssertion(?WebAuthnAuthenticatable $user = null)
    {
        return static::$app[WebAuthnAssertValidator::class]->generateAssertion($user);
    }

    /**
     * Returns a blank assertion request for user-less authentication.
     *
     * @return \Webauthn\PublicKeyCredentialRequestOptions
     */
    public static function generateBlankAssertion()
    {
        return static::$app[WebAuthnAssertValidator::class]->generateAssertion();
    }

    /**
     * Validates the attestation response, and returns the used credentials.
     *
     * It returns `false` when the validation fails.
     *
     * @param  array  $data
     * @return bool
     */
    public static function validateAssertion(array $data)
    {
        return (bool) static::$app[WebAuthnAssertValidator::class]->validate($data);
    }
}
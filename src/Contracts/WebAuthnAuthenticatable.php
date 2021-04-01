<?php

namespace DarkGhostHunter\Larapass\Contracts;

use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;

interface WebAuthnAuthenticatable
{
    /**
     * Creates an user entity information for attestation (registration).
     *
     * @return \Webauthn\PublicKeyCredentialUserEntity
     */
    public function userEntity(): PublicKeyCredentialUserEntity;

    /**
     * Return the handle used to identify his credentials.
     *
     * @return string
     */
    public function userHandle(): string;

    /**
     * Return a list of "blacklisted" credentials for attestation.
     *
     * @return array
     */
    public function attestationExcludedCredentials(): array;

    /**
     * Checks if a given credential exists.
     *
     * @param  string  $id
     *
     * @return bool
     */
    public function hasCredential(string $id): bool;

    /**
     * Register a new credential by its ID for this user.
     *
     * @param  \Webauthn\PublicKeyCredentialSource  $source
     *
     * @return void
     */
    public function addCredential(PublicKeyCredentialSource $source): void;

    /**
     * Removes a credential previously registered.
     *
     * @param  string|array  $id
     *
     * @return void
     */
    public function removeCredential($id): void;

    /**
     * Removes all credentials previously registered.
     *
     * @param  string|array|null  $except
     *
     * @return void
     */
    public function flushCredentials($except = null): void;

    /**
     * Checks if a given credential exists and is enabled.
     *
     * @param  string  $id
     *
     * @return bool
     */
    public function hasCredentialEnabled(string $id): bool;

    /**
     * Enable the credential for authentication.
     *
     * @param  string|array  $id
     *
     * @return void
     */
    public function enableCredential($id): void;

    /**
     * Disable the credential for authentication.
     *
     * @param  string|array  $id
     *
     * @return void
     */
    public function disableCredential($id): void;

    /**
     * Disables all credentials for the user.
     *
     * @param  string|array|null  $except
     *
     * @return void
     */
    public function disableAllCredentials($except = null): void;

    /**
     * Returns all credentials descriptors of the user.
     *
     * @return array|\Webauthn\PublicKeyCredentialDescriptor[]
     */
    public function allCredentialDescriptors(): array;

    /**
     * Sends a credential recovery email to the user.
     *
     * @param  string  $token
     *
     * @return void
     */
    public function sendCredentialRecoveryNotification(string $token): void;

    /**
     * Returns an WebAuthnAuthenticatable user from a given Credential ID.
     *
     * @param  string  $id
     *
     * @return \DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable|null
     */
    public static function getFromCredentialId(string $id): ?WebAuthnAuthenticatable;

    /**
     * Returns a WebAuthAuthenticatable user from a given User Handle.
     *
     * @param  string  $handle
     *
     * @return \DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable|null
     */
    public static function getFromCredentialUserHandle(string $handle): ?WebAuthnAuthenticatable;
}

<?php

namespace DarkGhostHunter\Larapass;

use DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable;
use DarkGhostHunter\Larapass\Eloquent\WebAuthnCredential;
use Illuminate\Support\Str;
use Webauthn\PublicKeyCredentialSource as CredentialSource;
use Webauthn\PublicKeyCredentialUserEntity as UserEntity;

/**
 * @property-read \Illuminate\Database\Eloquent\Collection|\DarkGhostHunter\Larapass\Eloquent\WebAuthnCredential[]
 *     $webAuthnCredentials
 */
trait WebAuthnAuthentication
{
    /**
     * @return \Illuminate\Database\Eloquent\Relations\HasMany|\DarkGhostHunter\Larapass\Eloquent\WebAuthnCredential
     */
    public function webAuthnCredentials()
    {
        return $this->hasMany(WebAuthnCredential::class);
    }

    /**
     * Creates an user entity information for attestation (registration).
     *
     * @return \Webauthn\PublicKeyCredentialUserEntity
     */
    public function userEntity(): UserEntity
    {
        return new UserEntity($this->email, $this->userHandle(), $this->name, $this->avatar);
    }

    /**
     * Return the handle used to identify his credentials.
     *
     * @return string
     */
    public function userHandle(): string
    {
        return $this->webAuthnCredentials()->withTrashed()->value('user_handle')
            ?? $this->generateUserHandle();
    }

    /**
     * Generate a new User Handle when it doesn't exists.
     *
     * @return string
     */
    protected function generateUserHandle()
    {
        return Str::uuid()->toString();
    }

    /**
     * Return a list of "blacklisted" credentials for attestation.
     *
     * @return array
     */
    public function attestationExcludedCredentials(): array
    {
        return $this->webAuthnCredentials()
            ->enabled()
            ->get()
            ->map->toCredentialDescriptor()
            ->values()
            ->all();
    }

    /**
     * Checks if a given credential exists.
     *
     * @param  string  $id
     *
     * @return bool
     */
    public function hasCredential(string $id): bool
    {
        return $this->webAuthnCredentials()->whereKey($id)->exists();
    }

    /**
     * Register a new credential by its ID for this user.
     *
     * @param  \Webauthn\PublicKeyCredentialSource  $source
     *
     * @return void
     */
    public function addCredential(CredentialSource $source): void
    {
        $this->webAuthnCredentials()->save(
            WebAuthnCredential::fromCredentialSource($source)
        );
    }

    /**
     * Removes a credential previously registered.
     *
     * @param  string|array  $id
     *
     * @return void
     */
    public function removeCredential($id): void
    {
        $this->webAuthnCredentials()->whereKey($id)->forceDelete();
    }

    /**
     * Removes all credentials previously registered.
     *
     * @param  string|array|null  $except
     *
     * @return void
     */
    public function flushCredentials($except = null): void
    {
        $this->webAuthnCredentials()->whereKeyNot($except)->forceDelete();
    }

    /**
     * Checks if a given credential exists and is enabled.
     *
     * @param  string  $id
     *
     * @return mixed
     */
    public function hasCredentialEnabled(string $id): bool
    {
        return $this->webAuthnCredentials()->whereKey($id)->enabled()->exists();
    }

    /**
     * Enable the credential for authentication.
     *
     * @param  string|array  $id
     *
     * @return void
     */
    public function enableCredential($id): void
    {
        $this->webAuthnCredentials()->whereKey($id)->restore();
    }

    /**
     * Disable the credential for authentication.
     *
     * @param  string|array  $id
     *
     * @return void
     */
    public function disableCredential($id): void
    {
        $this->webAuthnCredentials()->whereKey($id)->delete();
    }

    /**
     * Disables all credentials for the user.
     *
     * @param  string|array|null  $except
     *
     * @return void
     */
    public function disableAllCredentials($except = null): void
    {
        $this->webAuthnCredentials()->whereKeyNot($except)->delete();
    }

    /**
     * Returns all credentials descriptors of the user.
     *
     * @return array|\Webauthn\PublicKeyCredentialDescriptor[]
     */
    public function allCredentialDescriptors(): array
    {
        return $this->webAuthnCredentials()
            ->enabled()
            ->get()
            ->map->toCredentialDescriptor()
            ->values()
            ->all();
    }

    /**
     * Sends a credential recovery email to the user.
     *
     * @param  string  $token
     *
     * @return void
     */
    public function sendCredentialRecoveryNotification(string $token): void
    {
        $this->notify(new Notifications\AccountRecoveryNotification($token));
    }

    /**
     * Returns an WebAuthnAuthenticatable user from a given Credential ID.
     *
     * @param  string  $id
     *
     * @return \DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable|null
     */
    public static function getFromCredentialId(string $id): ?WebAuthnAuthenticatable
    {
        return static::whereHas(
            'webAuthnCredentials',
            static function ($query) use ($id) {
                return $query->whereKey($id);
            }
        )->first();
    }

    /**
     * Returns a WebAuthAuthenticatable user from a given User Handle.
     *
     * @param  string  $handle
     *
     * @return \DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable|null
     */
    public static function getFromCredentialUserHandle(string $handle): ?WebAuthnAuthenticatable
    {
        return static::whereHas(
            'webAuthnCredentials',
            static function ($query) use ($handle) {
                return $query->where('user_handle', $handle);
            }
        )->first();
    }
}

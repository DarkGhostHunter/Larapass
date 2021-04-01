<?php

namespace DarkGhostHunter\Larapass\Auth;

use DarkGhostHunter\Larapass\WebAuthn\WebAuthnAssertValidator;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Config\Repository as ConfigContract;
use Illuminate\Contracts\Hashing\Hasher as HasherContract;

class EloquentWebAuthnProvider extends EloquentUserProvider
{
    /**
     * If it should fallback to password credentials whenever possible.
     *
     * @var bool
     */
    protected $fallback;

    /**
     * WebAuthn assertion validator.
     *
     * @var \DarkGhostHunter\Larapass\WebAuthn\WebAuthnAssertValidator
     */
    protected WebAuthnAssertValidator $validator;

    /**
     * Create a new database user provider.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \DarkGhostHunter\Larapass\WebAuthn\WebAuthnAssertValidator  $validator
     * @param  \Illuminate\Contracts\Hashing\Hasher  $hasher
     * @param  string  $model
     */
    public function __construct(
        ConfigContract $config,
        WebAuthnAssertValidator $validator,
        HasherContract $hasher,
        string $model
    ) {
        $this->fallback = $config->get('larapass.fallback');
        $this->validator = $validator;

        parent::__construct($hasher, $model);
    }

    /**
     * Retrieve a user by the given credentials.
     *
     * @param  array  $credentials
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|\DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable|null|void
     */
    public function retrieveByCredentials(array $credentials)
    {
        if ($this->isSignedChallenge($credentials)) {
            return $this->model::getFromCredentialId($credentials['id']);
        }

        return parent::retrieveByCredentials($credentials);
    }

    /**
     * Check if the credentials are for a public key signed challenge
     *
     * @param  array  $credentials
     *
     * @return bool
     */
    protected function isSignedChallenge(array $credentials): bool
    {
        return isset($credentials['id'], $credentials['rawId'], $credentials['type'], $credentials['response']);
    }

    /**
     * Validate a user against the given credentials.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|\DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable  $user
     * @param  array  $credentials
     *
     * @return bool
     */
    public function validateCredentials($user, array $credentials): bool
    {
        if ($this->isSignedChallenge($credentials)) {
            return (bool)$this->validator->validate($credentials);
        }

        // If the fallback is enabled, we will validate the credential password.
        if ($this->fallback) {
            return parent::validateCredentials($user, $credentials);
        }

        return false;
    }
}

<?php

namespace DarkGhostHunter\Larapass\WebAuthn;

use DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Cache\Factory as CacheFactoryContract;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Contracts\Config\Repository as ConfigContract;
use Illuminate\Http\Request;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRpEntity as RelyingParty;

class WebAuthnAttestCreator
{
    /**
     * Application cache.
     *
     * @var \Illuminate\Contracts\Cache\Repository
     */
    protected Repository $cache;

    /**
     * Application as the Relying Party.
     *
     * @var \Webauthn\PublicKeyCredentialRpEntity
     */
    protected RelyingParty $relyingParty;

    /**
     * Authenticator filters.
     *
     * @var \Webauthn\AuthenticatorSelectionCriteria
     */
    protected AuthenticatorSelectionCriteria $criteria;

    /**
     * Parameters for the credentials creation.
     *
     * @var \DarkGhostHunter\Larapass\WebAuthn\PublicKeyCredentialParametersCollection
     */
    protected PublicKeyCredentialParametersCollection $parameters;

    /**
     * Custom extensions the user can accept from the client itself.
     *
     * @var \Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs
     */
    protected AuthenticationExtensionsClientInputs $extensions;

    /**
     * Challenge time-to-live, in milliseconds.
     *
     * @var int
     */
    protected int $timeout;

    /**
     * Number of bytes to create for a random challenge.
     *
     * @var mixed
     */
    protected $bytes;

    /**
     * If the devices should be further verified.
     *
     * @var string
     */
    protected string $conveyance;

    /**
     * If only one credential is allowed for the user in the device.
     *
     * @var bool
     */
    protected bool $unique;

    /**
     * Laravel HTTP Request.
     *
     * @var \Illuminate\Http\Request
     */
    protected Request $laravelRequest;

    /**
     * WebAuthnAttestation constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \Illuminate\Contracts\Cache\Factory  $cache
     * @param  \Webauthn\PublicKeyCredentialRpEntity  $relyingParty
     * @param  \Webauthn\AuthenticatorSelectionCriteria  $criteria
     * @param  \DarkGhostHunter\Larapass\WebAuthn\PublicKeyCredentialParametersCollection  $parameters
     * @param  \Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs  $extensions
     * @param  \Illuminate\Http\Request  $request
     */
    public function __construct(
        ConfigContract $config,
        CacheFactoryContract $cache,
        RelyingParty $relyingParty,
        AuthenticatorSelectionCriteria $criteria,
        PublicKeyCredentialParametersCollection $parameters,
        AuthenticationExtensionsClientInputs $extensions,
        Request $request
    ) {
        $this->cache = $cache->store($config->get('larapass.cache'));
        $this->relyingParty = $relyingParty;
        $this->criteria = $criteria;
        $this->parameters = $parameters;
        $this->extensions = $extensions;
        $this->laravelRequest = $request;

        $this->timeout = $config->get('larapass.timeout') * 1000;
        $this->bytes = $config->get('larapass.bytes');
        $this->conveyance = $config->get('larapass.conveyance');
        $this->unique = $config->get('larapass.unique');
    }

    /**
     * Retrieves an Attestation if it exists.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|\DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable  $user
     *
     * @return \Webauthn\PublicKeyCredentialCreationOptions|null
     */
    public function retrieveAttestation($user): ?PublicKeyCredentialCreationOptions
    {
        return $this->cache->get($this->cacheKey($user));
    }

    /**
     * Generates a new Attestation for a given user.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|\DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable  $user
     *
     * @return \Webauthn\PublicKeyCredentialCreationOptions
     */
    public function generateAttestation($user): PublicKeyCredentialCreationOptions
    {
        $attestation = $this->makeAttestationRequest($user);

        $this->cache->put($this->cacheKey($user), $attestation, $this->timeout);

        return $attestation;
    }

    /**
     * Returns the challenge that is remembered specifically for the user.
     *
     * @param  \DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable|\Illuminate\Contracts\Auth\Authenticatable  $user
     *
     * @return mixed
     */
    protected function makeAttestationRequest($user): PublicKeyCredentialCreationOptions
    {
        return new PublicKeyCredentialCreationOptions(
            $this->relyingParty,
            $user->userEntity(),
            random_bytes($this->bytes),
            $this->parameters->all(),
            $this->timeout,
            $this->getExcludedCredentials($user),
            $this->criteria,
            $this->conveyance,
            $this->extensions
        );
    }

    /**
     * Returns the cache key to remember the challenge for the user.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     *
     * @return string
     */
    protected function cacheKey(Authenticatable $user): string
    {
        return implode(
            '|',
            [
                'larapass.attestation',
                get_class($user) . ':' . $user->getAuthIdentifier(),
                sha1($this->laravelRequest->getHttpHost() . '|' . $this->laravelRequest->ip()),
            ]
        );
    }

    /**
     * Return the excluded credentials if the configuration demands it.
     *
     * @param  \DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable  $user
     *
     * @return array
     */
    protected function getExcludedCredentials(WebAuthnAuthenticatable $user): array
    {
        return $this->unique ? $user->attestationExcludedCredentials() : [];
    }
}

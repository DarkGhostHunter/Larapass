<?php

namespace DarkGhostHunter\Larapass\WebAuthn;

use Illuminate\Http\Request;
use InvalidArgumentException;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\AuthenticatorSelectionCriteria;
use Psr\Http\Message\ServerRequestInterface;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\PublicKeyCredentialRpEntity as RelyingParty;
use Illuminate\Contracts\Config\Repository as ConfigContract;
use Illuminate\Contracts\Cache\Factory as CacheFactoryContract;
use DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorAttestationResponseValidator as AttestationValidator;

class WebAuthnAttestValidator extends WebAuthnAttestCreator
{
    /**
     * Validator for the Attestation response.
     *
     * @var \Webauthn\AuthenticatorAttestationResponseValidator
     */
    protected $validator;

    /**
     * Loader for the raw credentials.
     *
     * @var \Webauthn\PublicKeyCredentialLoader
     */
    protected $loader;

    /**
     * Server Request
     *
     * @var \Psr\Http\Message\ServerRequestInterface
     */
    protected $request;

    /**
     * WebAuthnAttestation constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \Illuminate\Contracts\Cache\Factory  $cache
     * @param  \Webauthn\PublicKeyCredentialRpEntity  $relyingParty
     * @param  \Webauthn\AuthenticatorSelectionCriteria  $criteria
     * @param  \DarkGhostHunter\Larapass\WebAuthn\PublicKeyCredentialParametersCollection  $parameters
     * @param  \Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs  $extensions
     * @param  \Webauthn\AuthenticatorAttestationResponseValidator  $validator
     * @param  \Illuminate\Http\Request  $laravelRequest
     * @param  \Webauthn\PublicKeyCredentialLoader  $loader
     * @param  \Psr\Http\Message\ServerRequestInterface  $request
     */
    public function __construct(ConfigContract $config,
                                CacheFactoryContract $cache,
                                RelyingParty $relyingParty,
                                AuthenticatorSelectionCriteria $criteria,
                                PublicKeyCredentialParametersCollection $parameters,
                                AuthenticationExtensionsClientInputs $extensions,
                                AttestationValidator $validator,
                                Request $laravelRequest,
                                PublicKeyCredentialLoader $loader,
                                ServerRequestInterface $request)
    {
        $this->validator = $validator;
        $this->loader = $loader;
        $this->request = $request;

        parent::__construct(
            $config, $cache, $relyingParty, $criteria, $parameters, $extensions, $laravelRequest
        );
    }

    /**
     * Validates the incoming response from the Client.
     *
     * @param  array  $data
     * @param  \Illuminate\Contracts\Auth\Authenticatable|\DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable  $user
     * @return bool|\Webauthn\PublicKeyCredentialSource
     */
    public function validate(array $data, WebAuthnAuthenticatable $user)
    {
        if (! $request = $this->retrieveAttestation($user)) {
            return false;
        }

        try {
            $credentials = $this->loader->loadArray($data)->getResponse();

            if (! $credentials instanceof AuthenticatorAttestationResponse) {
                return false;
            }

            return $this->validator->check($credentials, $request, $this->request);
        }
        catch (InvalidArgumentException $exception) {
            return false;
        }
        finally {
            $this->cache->forget($this->cacheKey($user));
        }
    }
}
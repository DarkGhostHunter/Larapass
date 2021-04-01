<?php

namespace DarkGhostHunter\Larapass\WebAuthn;

use Illuminate\Contracts\Cache\Factory as CacheFactoryContract;
use Illuminate\Contracts\Config\Repository as ConfigContract;
use Illuminate\Http\Request;
use InvalidArgumentException;
use Psr\Http\Message\ServerRequestInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator as AttestationValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions as CreationOptions;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialRpEntity as RelyingParty;

class WebAuthnAttestValidator extends WebAuthnAttestCreator
{
    /**
     * Validator for the Attestation response.
     *
     * @var \Webauthn\AuthenticatorAttestationResponseValidator
     */
    protected AttestationValidator $validator;

    /**
     * Loader for the raw credentials.
     *
     * @var \Webauthn\PublicKeyCredentialLoader
     */
    protected PublicKeyCredentialLoader $loader;

    /**
     * Server Request
     *
     * @var \Psr\Http\Message\ServerRequestInterface
     */
    protected ServerRequestInterface $request;

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
    public function __construct(
        ConfigContract $config,
        CacheFactoryContract $cache,
        RelyingParty $relyingParty,
        AuthenticatorSelectionCriteria $criteria,
        PublicKeyCredentialParametersCollection $parameters,
        AuthenticationExtensionsClientInputs $extensions,
        AttestationValidator $validator,
        Request $laravelRequest,
        PublicKeyCredentialLoader $loader,
        ServerRequestInterface $request
    ) {
        $this->validator = $validator;
        $this->loader = $loader;
        $this->request = $request;

        parent::__construct(
            $config,
            $cache,
            $relyingParty,
            $criteria,
            $parameters,
            $extensions,
            $laravelRequest
        );
    }

    /**
     * Validates the incoming response from the Client.
     *
     * @param  array  $data
     * @param  \Illuminate\Contracts\Auth\Authenticatable|\DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable  $user
     *
     * @return bool|\Webauthn\PublicKeyCredentialSource
     */
    public function validate(array $data, $user)
    {
        if (!$attestation = $this->retrieveAttestation($user)) {
            return false;
        }

        try {
            $credentials = $this->loader->loadArray($data)->getResponse();

            if (!$credentials instanceof AuthenticatorAttestationResponse) {
                return false;
            }

            return $this->validator->check(
                $credentials,
                $attestation,
                $this->request,
                [$this->getCurrentRpId($attestation)]
            );
        } catch (InvalidArgumentException $exception) {
            return false;
        } finally {
            $this->cache->forget($this->cacheKey($user));
        }
    }

    /**
     * Returns the current Relaying Party ID to validate the response.
     *
     * @param  \Webauthn\PublicKeyCredentialCreationOptions  $attestation
     *
     * @return string
     */
    protected function getCurrentRpId(CreationOptions $attestation): string
    {
        return $attestation->getRp()->getId() ?? $this->laravelRequest->getHost();
    }
}

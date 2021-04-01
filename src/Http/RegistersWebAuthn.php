<?php

namespace DarkGhostHunter\Larapass\Http;

use DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable;
use DarkGhostHunter\Larapass\Events\AttestationSuccessful;
use DarkGhostHunter\Larapass\Facades\WebAuthn;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Webauthn\PublicKeyCredentialSource;

trait RegistersWebAuthn
{
    use WebAuthnRules;

    /**
     * Returns a challenge to be verified by the user device.
     *
     * @param  \DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable  $user
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function options(WebAuthnAuthenticatable $user): JsonResponse
    {
        return response()->json(WebAuthn::generateAttestation($user));
    }

    /**
     * Registers a device for further WebAuthn authentication.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable  $user
     *
     * @return \Illuminate\Http\Response
     */
    public function register(Request $request, WebAuthnAuthenticatable $user): Response
    {
        $input = $request->validate($this->attestationRules());

        // We'll validate the challenge coming from the authenticator and instantly
        // save it into the credentials store. If the data is invalid we will bail
        // out and return a non-authorized response since we can't save the data.
        $validCredential = WebAuthn::validateAttestation($input, $user);

        if ($validCredential) {
            $user->addCredential($validCredential);

            event(new AttestationSuccessful($user, $validCredential));

            return $this->credentialRegistered($user, $validCredential) ?? response()->noContent();
        }

        return response()->noContent(422);
    }

    /**
     * The user has registered a credential.
     *
     * @param  \DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable  $user
     * @param  \Webauthn\PublicKeyCredentialSource  $credentials
     *
     * @return void|mixed
     */
    protected function credentialRegistered(WebAuthnAuthenticatable $user, PublicKeyCredentialSource $credentials)
    {
        // ...
    }
}

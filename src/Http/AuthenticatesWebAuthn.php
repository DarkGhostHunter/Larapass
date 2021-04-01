<?php

namespace DarkGhostHunter\Larapass\Http;

use DarkGhostHunter\Larapass\Facades\WebAuthn;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Webauthn\PublicKeyCredentialRequestOptions;

trait AuthenticatesWebAuthn
{
    use WebAuthnRules;

    /**
     * Returns an WebAuthn Assertion challenge for the user (or userless).
     *
     * @param  \Illuminate\Http\Request  $request
     *
     * @return \Webauthn\PublicKeyCredentialRequestOptions
     */
    public function options(Request $request): PublicKeyCredentialRequestOptions
    {
        $credentials = $request->validate($this->optionRules());

        return WebAuthn::generateAssertion(
            $this->getUserFromCredentials($credentials)
        );
    }

    /**
     * Return the rules for validate the Request.
     *
     * @return array
     */
    protected function optionRules(): array
    {
        return [
            $this->username() => 'sometimes|email',
        ];
    }

    /**
     * Get the login user name to retrieve credentials ID.
     *
     * @return string
     */
    protected function username(): string
    {
        return 'email';
    }

    /**
     * Return the user that should authenticate via WebAuthn.
     *
     * @param  array  $credentials
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|\DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable|null
     */
    protected function getUserFromCredentials(array $credentials)
    {
        // We will try to ask the User Provider for any user for the given credentials.
        // If there is one, we will then return an array of credentials ID that the
        // authenticator may use to sign the subsequent challenge by the server.
        return $this->userProvider()->retrieveByCredentials($credentials);
    }

    /**
     * Get the User Provider for WebAuthn Authenticatable users.
     *
     * @return \Illuminate\Contracts\Auth\UserProvider
     */
    protected function userProvider(): UserProvider
    {
        return Auth::createUserProvider('users');
    }

    /**
     * Log the user in.
     *
     * @param  \Illuminate\Http\Request  $request
     *
     * @return \Illuminate\Http\Response|\Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        $credential = $request->validate($this->assertionRules());

        if ($authenticated = $this->attemptLogin($credential, $this->hasRemember($request))) {
            return $this->authenticated($request, $this->guard()->user()) ?? response()->noContent();
        }

        return response()->noContent(422);
    }

    /**
     * Check if the Request has a "Remember" value present.
     *
     * @param  \Illuminate\Http\Request  $request
     *
     * @return bool
     */
    protected function hasRemember(Request $request): bool
    {
        return filter_var($request->header('WebAuthn-Remember'), FILTER_VALIDATE_BOOLEAN)
            ?: $request->filled('remember');
    }

    /**
     * Attempt to log the user into the application.
     *
     * @param  array  $challenge
     * @param  bool  $remember
     *
     * @return bool
     */
    protected function attemptLogin(array $challenge, bool $remember = false): bool
    {
        return $this->guard()->attempt($challenge, $remember);
    }

    /**
     * The user has been authenticated.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  mixed  $user
     *
     * @return void|\Illuminate\Http\JsonResponse
     */
    protected function authenticated(Request $request, $user)
    {
        //
    }

    /**
     * Get the guard to be used during authentication.
     *
     * @return \Illuminate\Contracts\Auth\StatefulGuard
     */
    protected function guard(): StatefulGuard
    {
        return Auth::guard();
    }
}

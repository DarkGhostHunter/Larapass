<?php

namespace DarkGhostHunter\Larapass\Http;

use DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable;
use DarkGhostHunter\Larapass\Facades\WebAuthn;
use Illuminate\Http\Request;
use Webauthn\PublicKeyCredentialRequestOptions;

trait ConfirmsWebAuthn
{
    use WebAuthnRules;

    /**
     * Display the password confirmation view.
     *
     * @return \Illuminate\Contracts\Foundation\Application|\Illuminate\Contracts\View\Factory|\Illuminate\Contracts\View\View|\Illuminate\View\View
     */
    public function showConfirmForm()
    {
        return view('larapass::confirm');
    }

    /**
     * Return a request to assert the device.
     *
     * @param  \DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable  $user
     *
     * @return \Webauthn\PublicKeyCredentialRequestOptions
     */
    public function options(WebAuthnAuthenticatable $user): PublicKeyCredentialRequestOptions
    {
        return WebAuthn::generateAssertion($user);
    }

    /**
     * Confirm the device assertion.
     *
     * @param  \Illuminate\Http\Request  $request
     *
     * @return \Illuminate\Http\JsonResponse|\Illuminate\Http\RedirectResponse|\Illuminate\Http\Response
     */
    public function confirm(Request $request)
    {
        $credential = $request->validate($this->assertionRules());

        if (WebAuthn::validateAssertion($credential)) {
            $this->resetAuthenticatorConfirmationTimeout($request);

            return response()->json(['redirectTo' => redirect()->intended($this->redirectPath())->getTargetUrl()]);
        }

        return response()->noContent(422);
    }

    /**
     * Reset the password confirmation timeout.
     *
     * @param  \Illuminate\Http\Request  $request
     *
     * @return void
     */
    protected function resetAuthenticatorConfirmationTimeout(Request $request): void
    {
        $request->session()->put('auth.webauthn.confirm', now()->timestamp);
    }

    /**
     * Get the post recovery redirect path.
     *
     * @return string
     */
    public function redirectPath(): string
    {
        if (method_exists($this, 'redirectTo')) {
            return $this->redirectTo();
        }

        return property_exists($this, 'redirectTo') ? $this->redirectTo : '/home';
    }
}

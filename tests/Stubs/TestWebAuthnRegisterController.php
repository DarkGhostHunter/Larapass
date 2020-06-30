<?php

namespace Tests\Stubs;

use Illuminate\Routing\Controller;
use DarkGhostHunter\Larapass\Http\AttestsWebAuthn;

class TestWebAuthnRegisterController extends Controller
{
    use AttestsWebAuthn;

    /*
    |--------------------------------------------------------------------------
    | WebAuthn Registration Controller
    |--------------------------------------------------------------------------
    |
    | This controller receives an user request to register a device and also
    | verifies the registration. If everything goes ok, the credential is
    | persisted into the application, otherwise it will signal failure.
    |
    */

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth');
    }
}
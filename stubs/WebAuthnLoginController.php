<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use DarkGhostHunter\Larapass\Http\AuthenticatesWebAuthn;

class WebAuthnLoginController extends Controller
{
    use AuthenticatesWebAuthn;

    /*
    |--------------------------------------------------------------------------
    | WebAuthn Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller allows the WebAuthn user device to request a login and
    | return the correctly signed challenge. Most of the hard work is done
    | by your Authentication Guard once the user is attempting to login.
    |
    */

    public function __construct()
    {
        $this->middleware(['guest', 'throttle:10,1']);
    }
}
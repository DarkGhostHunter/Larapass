<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use DarkGhostHunter\Larapass\Http\RecoversWebAuthn;

class TestWebAuthnRecoveryController extends Controller
{
    use RecoversWebAuthn;

    /*
    |--------------------------------------------------------------------------
    | WebAuthn Recovery Controller
    |--------------------------------------------------------------------------
    |
    | When an user loses his device he will reach this controller to attach a
    | new device. The user will attach a new device, and optionally, disable
    | all others. Then he will be authenticated and redirected to your app.
    |
    */

    /**
     * Where to redirect users after resetting their password.
     *
     * @var string
     */
    protected $redirectTo = '/home';

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('throttle:10,1')->only('options', 'recover');
    }
}
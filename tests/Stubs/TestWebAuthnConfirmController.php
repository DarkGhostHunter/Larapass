<?php

namespace Tests\Stubs;

use App\Http\Controllers\Controller;
use DarkGhostHunter\Larapass\Http\ConfirmsWebAuthn;

class TestWebAuthnConfirmController extends Controller
{
    use ConfirmsWebAuthn;

    /*
    |--------------------------------------------------------------------------
    | Confirm Device Controller
    |--------------------------------------------------------------------------
    |
    | This controller is responsible for handling WebAuthn confirmations and
    | uses a simple trait to include the behavior. You're free to explore
    | this trait and override any functions that require customization.
    |
    */

    /**
     * Where to redirect users when the intended url fails.
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
        $this->middleware('auth');
    }

}
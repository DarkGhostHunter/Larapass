<?php

namespace DarkGhostHunter\Larapass\Http\Middleware;

use Closure;
use Illuminate\Contracts\Session\Session;
use Illuminate\Contracts\Routing\UrlGenerator;
use Illuminate\Contracts\Routing\ResponseFactory;

class ConfirmWebAuthn
{
    /**
     * The response factory instance.
     *
     * @var \Illuminate\Contracts\Routing\ResponseFactory
     */
    protected $responseFactory;

    /**
     * The URL generator instance.
     *
     * @var \Illuminate\Contracts\Routing\UrlGenerator
     */
    protected $urlGenerator;

    /**
     * The password timeout.
     *
     * @var int
     */
    protected $remember;

    /**
     * @var \Illuminate\Contracts\Session\Session
     */
    protected $session;

    /**
     * Create a new middleware instance.
     *
     * @param  \Illuminate\Contracts\Routing\ResponseFactory  $responseFactory
     * @param  \Illuminate\Contracts\Routing\UrlGenerator  $urlGenerator
     * @param  \Illuminate\Contracts\Session\Session  $session
     * @param  int|null  $remember
     */
    public function __construct(ResponseFactory $responseFactory,
                                UrlGenerator $urlGenerator,
                                Session $session,
                                $remember = 10800)
    {
        $this->responseFactory = $responseFactory;
        $this->urlGenerator = $urlGenerator;
        $this->session = $session;
        $this->remember = $remember;
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string  $redirectToRoute
     * @return mixed
     */
    public function handle($request, Closure $next, $redirectToRoute = 'webauthn.confirm.form')
    {
        if ($this->shouldConfirmAuthenticator()) {
            if ($request->expectsJson()) {
                return $this->responseFactory->json([
                    'message' => 'Authenticator assertion required.',
                ], 423);
            }

            return $this->responseFactory->redirectGuest(
                $this->urlGenerator->route($redirectToRoute)
            );
        }

        return $next($request);
    }

    /**
     * Determine if the confirmation timeout has expired.
     *
     * @return bool
     */
    protected function shouldConfirmAuthenticator()
    {
        $confirmedAt = now()->timestamp - $this->session->get('auth.webauthn.confirm', 0);

        return $confirmedAt > $this->remember;
    }
}
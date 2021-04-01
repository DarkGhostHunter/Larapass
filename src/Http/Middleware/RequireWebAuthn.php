<?php

namespace DarkGhostHunter\Larapass\Http\Middleware;

use Closure;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Routing\ResponseFactory;
use Illuminate\Contracts\Routing\UrlGenerator;
use Illuminate\Contracts\Session\Session;

class RequireWebAuthn
{
    /**
     * The response factory instance.
     *
     * @var \Illuminate\Contracts\Routing\ResponseFactory
     */
    protected ResponseFactory $responseFactory;

    /**
     * The URL generator instance.
     *
     * @var \Illuminate\Contracts\Routing\UrlGenerator
     */
    protected UrlGenerator $urlGenerator;

    /**
     * The password timeout.
     *
     * @var int
     */
    protected int $remember;

    /**
     * @var \Illuminate\Contracts\Session\Session
     */
    protected Session $session;

    /**
     * Create a new middleware instance.
     *
     * @param  \Illuminate\Contracts\Routing\ResponseFactory  $responseFactory
     * @param  \Illuminate\Contracts\Routing\UrlGenerator  $urlGenerator
     * @param  \Illuminate\Contracts\Session\Session  $session
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(
        ResponseFactory $responseFactory,
        UrlGenerator $urlGenerator,
        Session $session,
        Repository $config
    ) {
        $this->responseFactory = $responseFactory;
        $this->urlGenerator = $urlGenerator;
        $this->session = $session;
        $this->remember = $config->get('larapass.confirm_timeout', 10800);
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string  $redirectToRoute
     *
     * @return mixed
     */
    public function handle($request, Closure $next, $redirectToRoute = 'webauthn.confirm.form')
    {
        if ($this->shouldConfirmAuthenticator()) {
            if ($request->expectsJson()) {
                return $this->responseFactory->json(['message' => 'Authenticator assertion required.'], 423);
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
    protected function shouldConfirmAuthenticator(): bool
    {
        $confirmedAt = now()->timestamp - $this->session->get('auth.webauthn.confirm', 0);

        return $confirmedAt > $this->remember;
    }
}

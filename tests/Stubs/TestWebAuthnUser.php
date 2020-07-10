<?php

namespace Tests\Stubs;

use Illuminate\Foundation\Auth\User;
use Illuminate\Notifications\Notifiable;
use DarkGhostHunter\Larapass\WebAuthnAuthentication;
use DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable;
use DarkGhostHunter\Larapass\Eloquent\WebAuthnCredential as WebAuthModel;

/**
 * @mixin \Illuminate\Database\Eloquent\Builder
 */
class TestWebAuthnUser extends User implements WebAuthnAuthenticatable
{
    use WebAuthnAuthentication,
        Notifiable;

    protected $table = 'users';

    /**
     * @return \Illuminate\Database\Eloquent\Relations\HasMany|\DarkGhostHunter\Larapass\Eloquent\WebAuthnCredential
     */
    public function webAuthnCredentials()
    {
        return $this->hasMany(WebAuthModel::class, 'user_id');
    }
}
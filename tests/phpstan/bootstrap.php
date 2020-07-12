<?php

config()->set('larapass.relaying_party.name', 'test');
config()->set('auth.passwords.webauthn', [
    'provider' => 'users',
    'table' => 'web_authn_recoveries',
    'expire' => 60,
    'throttle' => 60,
]);

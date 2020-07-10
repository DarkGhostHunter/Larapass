<?php

return [
    'title' => 'Account recovery',

    'description' => 'If you can\'t login with your device, you can register another by opening an email there.',
    'details'     => 'Ensure you open the email on a device you fully own.',

    'instructions' => 'Press the button to use this device for your account and follow your the instructions.',
    'unique'       => 'Disable all others devices except this.',

    'button' => [
        'send'     => 'Send account recovery',
        'register' => 'Register this device',
    ],

    'sent'      => 'If the email is correct, you should receive an email with a recovery link shortly.',
    'attached'  => 'A new device has been attached to your account to authenticate.',
    'user'      => 'We can\'t find a user with that email address.',
    'token'     => 'The token is invalid or has expired.',
    'throttled' => 'Please wait before retrying.',

    'failed'    => 'The recovery failed. Try again.',
];
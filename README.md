![Lukenn Sabellano - Unsplash (UL) #RDufjtg6JpQ](https://images.unsplash.com/photo-1567826722186-9ecdf689f122?ixlib=rb-1.2.1&auto=format&fit=crop&w=1280&h=400&q=80)

[![Latest Stable Version](https://poser.pugx.org/darkghosthunter/larapass/v/stable)](https://packagist.org/packages/darkghosthunter/larapass) [![License](https://poser.pugx.org/darkghosthunter/larapass/license)](https://packagist.org/packages/darkghosthunter/larapass) ![](https://img.shields.io/packagist/php-v/darkghosthunter/larapass.svg) ![](https://github.com/DarkGhostHunter/Larapass/workflows/PHP%20Composer/badge.svg) [![Coverage Status](https://coveralls.io/repos/github/DarkGhostHunter/Larapass/badge.svg?branch=master)](https://coveralls.io/github/DarkGhostHunter/Larapass?branch=master) [![Laravel Octane Compatible](https://img.shields.io/badge/Laravel%20Octane-Compatible-success?style=flat&logo=laravel)](https://github.com/laravel/octane)

## Larapass

Authenticate users with just their device, fingerprint or biometric data. Goodbye passwords!

This enables WebAuthn authentication inside Laravel authentication driver, and comes with _everything but the kitchen sink_. 

## Requisites

* PHP 7.4 or PHP 8.0
* Laravel 7.18 (July 2020) or Laravel 8.x

## Installation 

Just hit the console and require it with Composer.

    composer require darkghosthunter/larapass

Unfortunately, using WebAuthn is not a "walk in the park", this package allows you to enable WebAuthn in the most **easiest way possible**.

# Table of contents

- [What is WebAuthn? How it uses fingerprints or else?](#what-is-webauthn-how-it-uses-fingerprints-or-else)
- [Set up](#set-up)
- [Confirmation Middleware](#confirmation-middleware)
- [Events](#events)
- [Operations with WebAuthn](#operations-with-webauthn)
- [Advanced Configuration](#advanced-configuration)
  - [Relaying Party Information](#relaying-party-information)
  - [Challenge configuration](#challenge-configuration)
  - [Algorithms](#algorithms)
  - [Key Attachment](#key-attachment)
  - [Attestation conveyance](#attestation-conveyance)
  - [Login verification](#login-verification)
  - [Userless login (One touch, Typeless)](#userless-login-one-touch-typeless)
  - [Unique](#unique)
  - [Password Fallback](#password-fallback)
  - [Confirmation timeout](#confirmation-timeout)
- [Attestation and Metadata statements support](#attestation-and-metadata-statements-support)
- [Security](#security)
- [FAQ](#faq)
- [License](#license)

## What is WebAuthn? How it uses fingerprints or else?

In a nutshell, [major browsers are compatible with Web Authentication API](https://caniuse.com/#feat=webauthn), pushing authentication to the device (fingerprints, Face ID, patterns, codes, etc) instead of plain-text passwords.

This package validates the WebAuthn payload from the devices using a custom [user provider](https://laravel.com/docs/authentication#adding-custom-user-providers).

If you have any doubts about WebAuthn, [check this small FAQ](#faq). For a more deep dive, check [WebAuthn.io](https://webauthn.io/), [WebAuthn.me](https://webauthn.me/) and [Google WebAuthn tutorial](https://codelabs.developers.google.com/codelabs/webauthn-reauth/).

## Set up

We need to make sure your users can register their devices and authenticate with them.

1. [Add the `eloquent-webauthn` driver](#1-add-the-eloquent-webauthn-driver).
2. [Create the `webauthn_credentials` table.](#2-create-the-webauthn_credentials-table)
3. [Implement the contract and trait](#3-implement-the-contract-and-trait)

After that, you can quickly start WebAuthn with the included controllers and helpers to make your life easier.

4. [Register the routes](#4-register-the-routes-optional)
5. [Use the Javascript helper](#5-use-the-javascript-helper-optional)
6. [Set up account recovery](#6-set-up-account-recovery-optional)

### 1. Add the `eloquent-webauthn` driver

This package comes with an Eloquent-compatible [user provider](https://laravel.com/docs/authentication#adding-custom-user-providers) that validates WebAuthn responses from the devices.

Go to your `config/auth.php` configuration file, and change the driver of the provider you're using to `eloquent-webauthn`.

```php
return [
    // ...

    'providers' => [
        'users' => [
            // 'driver' => 'eloquent', // Default Eloquent User Provider 
            'driver' => 'eloquent-webauthn',
            'model' => App\User::class,
        ],
    ]
];
```

> If you plan to create your own user provider driver for WebAuthn, remember to inject the [`WebAuthnAssertValidator`](src/WebAuthn/WebAuthnAssertValidator.php) to properly validate the user with the incoming response.

### 2. Create the `webauthn_credentials` table

Create the `webauthn_credentials` table by publishing the migration files and migrating the table:

    php artisan vendor:publish --provider="DarkGhostHunter\Larapass\LarapassServiceProvider" --tag="migrations"
    php artisan migrate

### 3. Implement the contract and trait

Add the `WebAuthnAuthenticatable` contract and the `WebAuthnAuthentication` trait to the `Authenticatable` user class, or any that uses authentication.

```php
<?php

namespace App;

use Illuminate\Foundation\Auth\User as Authenticatable;
use DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable;
use DarkGhostHunter\Larapass\WebAuthnAuthentication;

class User extends Authenticatable implements WebAuthnAuthenticatable
{
    use WebAuthnAuthentication;

    // ...
}
```

> The trait is used to tie the User model to the WebAuthn data contained in the database.

### 4. Register the routes (optional)

Finally, you will need to add the routes for registering and authenticating users. If you want a quick start, just publish the controllers included in Larapass.

    php artisan vendor:publish --provider="DarkGhostHunter\Larapass\LarapassServiceProvider" --tag="controllers"
 
You can copy-paste these route definitions in your `routes/web.php` file. 

```php
use App\Http\Controllers\Auth\WebAuthnRegisterController;
use App\Http\Controllers\Auth\WebAuthnLoginController;

Route::post('webauthn/register/options', [WebAuthnRegisterController::class, 'options'])
     ->name('webauthn.register.options');
Route::post('webauthn/register', [WebAuthnRegisterController::class, 'register'])
     ->name('webauthn.register');

Route::post('webauthn/login/options', [WebAuthnLoginController::class, 'options'])
     ->name('webauthn.login.options');
Route::post('webauthn/login', [WebAuthnLoginController::class, 'login'])
     ->name('webauthn.login');
```

In your frontend scripts, point the requests to these routes.

> If you want full control, you can opt-out of these helper controllers and use your own logic. Use the [`AttestWebAuthn`](src/Http/RegistersWebAuthn.php) and [`AssertsWebAuthn`](src/Http/AuthenticatesWebAuthn.php) traits if you need to start with something.

### 5. Use the Javascript helper (optional)

This package includes a convenient script to handle registration and login via WebAuthn. To use it, just publish the `larapass.js` asset into your application public resources.

    php artisan vendor:publish --provider="DarkGhostHunter\Larapass\LarapassServiceProvider" --tag="public"

You will receive the `vendor/larapass/js/larapass.js` file which you can include into your authentication views and use it programmatically, anyway you want.

```html
<script src="{{ asset('vendor/larapass/js/larapass.js') }}"></script>

<!-- Registering credentials -->
<script>
    const register = (event) => {
        event.preventDefault()
        new Larapass({
            register: 'webauthn/register',
            registerOptions: 'webauthn/register/options'
        }).register()
          .then(response => alert('Registration successful!'))
          .catch(response => alert('Something went wrong, try again!'))
    }

    document.getElementById('register-form').addEventListener('submit', register)
</script>

<!-- Login users -->
<script>
    const login = (event) => {
        event.preventDefault()
        new Larapass({
            login: 'webauthn/login',
            loginOptions: 'webauthn/login/options'
        }).login({
            email: document.getElementById('email').value
        }).then(response => alert('Authentication successful!'))
          .catch(error => alert('Something went wrong, try again!'))
    }

    document.getElementById('login-form').addEventListener('submit', login)
</script>
```

> You can bypass the route list declaration if you're using the defaults. The example above includes them just for show. Be sure to create modify this script for your needs.

Also, the helper allows headers on the action request, on both registration and login.

```javascript
new Larapass({
    login: 'webauthn/login',
    loginOptions: 'webauthn/login/options'
}).login({
    email: document.getElementById('email').value,
}, {
    'My-Custom-Header': 'This is sent with the signed challenge',
})
```

> You can copy-paste it and import into a transpiler like [Laravel Mix](https://laravel.com/docs/mix#running-mix), [Babel](https://babeljs.io/) or [Webpack](https://webpack.js.org/). If the script doesn't suit your needs, you're free to create your own.

#### Remembering Users

You can enable it by just issuing the `WebAuthn-Remember` header value to `true` when pushing the signed login challenge from your frontend. We can do this easily with the [included Javascript helper](#5-use-the-javascript-helper-optional).

```javascript
new Larapass.login({
    email: document.getElementById('email').value
}, {
    'WebAuthn-Remember': true
})
```

Alternatively, you can add the `remember` key to the outgoing JSON Payload if you're using your own scripts. Both ways are accepted.

> You can override this behaviour in the [`AssertsWebAuthn`](src/Http/AuthenticatesWebAuthn.php) trait.

### 6. Set up account recovery (optional)

Probably you will want to offer a way to "recover" an account if the user loses his credentials, which is basically a way to attach a new one. You can use controllers [which are also published](#4-register-the-routes-optional), along with these routes:

```php
use App\Http\Controllers\Auth\WebAuthnDeviceLostController;
use App\Http\Controllers\Auth\WebAuthnRecoveryController;

Route::get('webauthn/lost', [WebAuthnDeviceLostController::class, 'showDeviceLostForm'])
     ->name('webauthn.lost.form');
Route::post('webauthn/lost', [WebAuthnDeviceLostController::class, 'sendRecoveryEmail'])
     ->name('webauthn.lost.send');

Route::get('webauthn/recover', [WebAuthnRecoveryController::class, 'showResetForm'])
     ->name('webauthn.recover.form');
Route::post('webauthn/recover/options', [WebAuthnRecoveryController::class, 'options'])
     ->name('webauthn.recover.options');
Route::post('webauthn/recover/register', [WebAuthnRecoveryController::class, 'recover'])
     ->name('webauthn.recover');
```

These come with [new views](resources/views) and [translation lines](resources/lang), so you can override them if you're not happy with what is included. 

You can also override the views in `resources/vendor/larapass` and the notification being sent using the `sendCredentialRecoveryNotification` method of the user.

After that, don't forget to add a new token broker in your `config/auth.php`. We will need it to store the tokens from the recovery procedure.

```php
return [
    // ...

    'passwords' => [
        'users' => [
            'provider' => 'users',
            'table' => 'password_resets',
            'expire' => 60,
            'throttle' => 60,
        ],

        // New for WebAuthn
        'webauthn' => [
            'provider' => 'users', // The user provider using WebAuthn.
            'table' => 'web_authn_recoveries', // The table to store the recoveries.
            'expire' => 60,
            'throttle' => 60,
        ],
    ],
];
```

## Confirmation middleware

Following the same principle of the [`password.confirm` middleware](https://laravel.com/docs/authentication#password-confirmation), Larapass includes a the `webauthn.confirm` middleware that will ask the user to confirm with his device before entering a given route.

```php
Route::get('this/is/important', function () {
    return 'This is very important!';
})->middleware('webauthn.confirm');
```

When [publishing the controllers](#4-register-the-routes-optional), the `WebAuthnConfirmController` will be in your controller files ready to accept confirmations. You just need to register the route by just copy-pasting these:

```php
Route::get('webauthn/confirm', 'Auth\WebAuthnConfirmController@showConfirmForm')
     ->name('webauthn.confirm.form');
Route::post('webauthn/confirm/options', 'Auth\WebAuthnConfirmController@options')
     ->name('webauthn.confirm.options');
Route::post('webauthn/confirm', 'Auth\WebAuthnConfirmController@confirm')
     ->name('webauthn.confirm');
```

As always, you can opt-out with your own logic. For these case take a look into the [`ConfirmsWebAuthn`](src/Http/ConfirmsWebAuthn.php) trait to start.

> You can change how much time to remember the confirmation [in the configuration](#confirmation-timeout).

## Events

Since all authentication is handled by Laravel itself, the only [event](https://laravel.com/docs/events) included is [`AttestationSuccessful`](src/Events/AttestationSuccessful.php), which fires when the registration is successful. It includes the user with the credentials persisted.

You can use this event to, for example, notify the user a new device has been registered. For that, you can use a [listener](https://laravel.com/docs/events#defining-listeners).

```php
public function handle(AttestationSuccessful $event)
{
    $event->user->notify(
        new DeviceRegisteredNotification($event->credential->getId())
    );
}
```

## Operations with WebAuthn

This package simplifies operating with the WebAuthn _ceremonies_ (attestation and assertion). For this, use the convenient [`WebAuthn`](src/Facades/WebAuthn.php) facade.

### Attestation (Register)

Use the `generateAttestation` and `validateAttestation` for your user. The latter returns the credentials validated, so you can save them manually.

```php
<?php

use App\User; 
use Illuminate\Support\Facades\Auth;
use DarkGhostHunter\Larapass\Facades\WebAuthn;

$user = Auth::user();

// Create an attestation for a given user.
return WebAuthn::generateAttestation($user);
```

Then later we can verify it:

```php
<?php

use App\User; 
use Illuminate\Support\Facades\Auth;
use DarkGhostHunter\Larapass\Facades\WebAuthn;

$user = Auth::user();

// Verify it
$credential = WebAuthn::validateAttestation(
    request()->json()->all(), $user
);

// And save it.
if ($credential) {
    $user->addCredential($credential);
} else {
    return 'Something went wrong with your device!';
}
```

### Assertion (Login)

For assertion, simply create a request using `generateAssertion` and validate it with `validateAssertion`.

```php
<?php

use App\User; 
use DarkGhostHunter\Larapass\Facades\WebAuthn;

// Find the user to assert, if there is any
$user = User::where('email', request()->input('email'))->first();

// Create an assertion for the given user (or a blank one if not found);
return WebAuthn::generateAssertion($user);
```

Then later we can verify it:

```php
<?php

use App\User;
use Illuminate\Support\Facades\Auth;
use DarkGhostHunter\Larapass\Facades\WebAuthn;

// Verify the incoming assertion.
$credentials = WebAuthn::validateAssertion(
    request()->json()->all()
);

// If is valid, login the user of the credentials.
if ($credentials) {
    Auth::login(
        User::getFromCredentialId($credentials->getPublicKeyCredentialId())
    );
}
```

### Credentials

You can manage the user credentials thanks to the [`WebAuthnAuthenticatable`](src/Contracts/WebAuthnAuthenticatable.php) contract directly from within the user instance. The most useful methods are:

* `hasCredential()`: Checks if the user has a given Credential ID.
* `addCredential()`: Adds a new Credential Source.
* `removeCredential()`: Removes an existing Credential by its ID.
* `flushCredentials()`: Removes all credentials. You can exclude credentials by their id.
* `enableCredential()`: Includes an existing Credential ID from authentication.
* `disableCredential()`: Excludes an existing Credential ID from authentication.
* `getFromCredentialId()`: Returns the user using the given Credential ID, if any.

You can use these methods to, for example, blacklist a stolen device/credential and register a new one, or disable WebAuthn completely by flushing all registered devices.

## Advanced Configuration

Larapass was made to work out-of-the-box, but you can override the configuration by simply publishing the config file.

    php artisan vendor:publish --provider="DarkGhostHunter\Larapass\LarapassServiceProvider" --tag="config"

After that, you will receive the `config/larapass.php` config file with an array like this:

```php
<?php

return [
    'relaying_party' => [
        'name' => env('WEBAUTHN_NAME', env('APP_NAME')),
        'id'   => env('WEBAUTHN_ID'),
        'icon' => env('WEBAUTHN_ICON'),
    ],
    'bytes' => 16,
    'timeout' => 60,
    'cache' => env('WEBAUTHN_CACHE'),
    'algorithms' => [
        \Cose\Algorithm\Signature\ECDSA\ES256::class,
        \Cose\Algorithm\Signature\EdDSA\Ed25519::class,
        \Cose\Algorithm\Signature\ECDSA\ES384::class,
        \Cose\Algorithm\Signature\ECDSA\ES512::class,
        \Cose\Algorithm\Signature\RSA\RS256::class,
    ],
    'attachment' => null,
    'conveyance' => 'none',
    'login_verify' => 'preferred',
    'userless' => null,
    'unique' => false,
    'fallback' => true,
    'confirm_timeout' => 10800,
];
```

### Relaying Party Information

```php
return [
    'relaying_party' => [
        'name' => env('WEBAUTHN_NAME', env('APP_NAME')),
        'id'   => env('WEBAUTHN_ID'),
        'icon' => env('WEBAUTHN_ICON'),
    ],
];
```

The _Relaying Party_ is just a way to uniquely identify your application in the user device:

* `name`: The name of the application. Defaults to the application name.
* `id`: Optional domain of the application. If null, the device will fill it internally.
* `icon`: Optional image data in BASE64 (128 bytes maximum) or an image url.

> Consider using the base domain like `myapp.com` as `id` to allow all the credential on subdomains like `foo.myapp.com`.

### Challenge configuration

```php
return [
    'bytes' => 16,
    'timeout' => 60,
    'cache' => env('WEBAUTHN_CACHE'),
];
```

The outgoing challenge to be signed is a random string of bytes. This controls how many bytes, the timeout of the challenge (which after is marked as invalid), and the cache used to store the challenge while its being resolved by the device.

### Algorithms

```php
return [
    'algorithms' => [
        \Cose\Algorithm\Signature\ECDSA\ES256::class,   // ECDSA with SHA-256
        \Cose\Algorithm\Signature\EdDSA\Ed25519::class, // EdDSA
        \Cose\Algorithm\Signature\ECDSA\ES384::class,   // ECDSA with SHA-384
        \Cose\Algorithm\Signature\ECDSA\ES512::class,   // ECDSA with SHA-512
        \Cose\Algorithm\Signature\RSA\RS256::class,     // RSASSA-PKCS1-v1_5 with SHA-256
    ],
];
```

This controls how the authenticator (device) will operate to create the public-private keys. These [COSE Algorithms](https://w3c.github.io/webauthn/#typedefdef-cosealgorithmidentifier) are the most compatible ones for in-device and roaming keys, since some must be transmitted on low bandwidth protocols.

> Add or remove the classes unless you don't know what you're doing. Really. Just leave them as they are.

### Key Attachment

```php
return [
     'attachment' => null,
];
```

By default, the user decides what to use for registration. If you wish to exclusively use a cross-platform authentication (like USB Keys, CA Servers or Certificates) set this to `true`, or `false` if you want to enforce device-only authentication. 

### Attestation conveyance

```php
return [
    'conveyance' => null,
];
```

Attestation Conveyance represents if the device key should be verified by you or not. While most of the time is not needed, you can change this to `indirect` (you verify it comes from a trustful source) or `direct` (the device includes validation data).

> Leave as it if you don't know what you're doing.

### Login verification

```php
return [
    'login_verify' => 'preferred',
];
```

By default, most authenticators will require the user verification when login in. You can override this and set it as `required` if you want no exceptions.

You can also use `discouraged` to only check for user presence (like a "Continue" button), which may make the login faster but making it slightly less secure.

> When setting [userless](#userless-login-one-touch-typeless) as `preferred` or `required` will override this to `required` automatically.

### Userless login (One touch, Typeless)

```php
return [
    'userless' => null,
];
```

You can activate _userless_ login, also known as one-touch login or typless login, for devices when they're being registered. You should change this to `preferred` in that case, since not all devices support the feature.

If this is activated (not `null` or `discouraged`), login verification will be mandatory.

> This doesn't affect the login procedure, only the attestation (registration).

### Unique

```php
return [
    'unique' => false,
];
```

If true, the device will limit the creation of only one credential by device. This is done by telling the device the list of credentials ID the user already has. If at least one if already present in the device, the latter will return an error.

### Password Fallback

```php
return [
    'fallback' => true,
];
```

By default, this package allows to re-use the same `eloquent-webauthn` driver to log in users with passwords when the credentials are not a WebAuthn JSON payload.

Disabling the fallback will only validate the WebAuthn credentials. To handle classic user/password scenarios, you may create a separate guard.

### Confirmation timeout

```php
return [
    'confirm_timeout' => 10800,
];
```

When using the [Confirmation middleware](#confirmation-middleware), the confirmation will be remembered for a set amount of seconds. By default, is 3 hours, which is enough for most scenarios.

## Attestation and Metadata statements support

If you need very-high-level of security, you should use attestation and metadata statements. You will basically ask the authenticator for its authenticity and check it in a lot of ways.

For that, [check this article](https://webauthn-doc.spomky-labs.com/deep-into-the-framework/attestation-and-metadata-statement) and extend the classes in the Service Container as you need:

```php
<?php

use Webauthn\AttestationStatement\AttestationStatementSupport;
use Webauthn\AttestationStatement\AndroidSafetyNetAttestationStatementSupport;

$this->app->extend(AttestationStatementSupport::class, function ($manager) {
    $manager->add(new AndroidSafetyNetAttestationStatementSupport());
});
```

## Security

These are some details about this WebAuthn implementation:

* Registration (attestation) is exclusive to the domain, IP and user.
* Login (assertion) is exclusive to the domain, IP, and the user if specified
* Cached challenge is always forgotten after resolution, independently of the result.
* Cached challenge TTL is the same as the WebAuthn timeout (60 seconds default).
* Included controllers include throttling for WebAuthn endpoints.
* Users ID (handle) is a random UUID v4.
* Credentials can be blacklisted (enabled/disabled).

If you discover any security related issues, please email darkghosthunter@gmail.com instead of using the issue tracker.

> As a sidenote, remember to [configure your application properly if it's behind a load balancer](https://laravel.com/docs/requests#configuring-trusted-proxies).

## FAQ

* **Does this work with any browser?**

[Yes](https://caniuse.com/#feat=webauthn). In the case of old browsers, you should have a fallback detection script. This can be asked with [the included Javascript helper](#5-use-the-javascript-helper-optional) in a breeze:

```javascript
if (! Larapass.supportsWebAuthn()) {
   alert('Your device is not secure enough to use this site!');
}
```

* **Does this stores the user's fingerprint, PIN or patterns in my site?**

No. It stores the public key generated by the device.

* **Can a phishing site steal WebAuthn credentials and use them in my site?**

No. WebAuthn kills phishing.

* **Can the WebAuthn data identify a particular device?**

No, unless explicitly requested and consented.

* **Are my user's classic passwords safe?**

Yes, as long you are hashing them as you should, and you have secured your application key. This is done by Laravel by default. You can also [disable them](#password-fallback).

* **Can a user register two or more _devices_?**

Yes.

* **What happens if a credential is cloned?**

The user won't be authenticated since the "logins" counter will be greater than the reported by the original device. To intercede in the procedure, modify the Assertion Validator in the Service Container and add your own `CounterChecker`:

```php
$this->app->bind(CounterChecker::class, function () {
    return new \App\WebAuthn\MyCountChecker;
});
```

Inside your counter checker, you may want to throw an exception if the counter is below what is reported.

```php
<?php

namespace App\WebAuthn;

use Webauthn\Counter\CounterChecker;
use App\Exceptions\WebAuthn\CredentialCloned;
use Webauthn\PublicKeyCredentialSource as Credentials;

class MyCountChecker implements CounterChecker
{
    public function check(Credentials $credentials, int $currentCounter) : void
    {
        if ($credentials->getCounter() <= $currentCounter) {
            throw new CredentialCloned($credentials);
        } 
    }
}
```

* **If a user loses his device, can he register a new device?**

Yes, [use these recovery helpers](#6-set-up-account-recovery-optional).

* **What's the difference between disabling and deleting a credential?**

Disabling a credential doesn't delete it, so it can be later enabled manually in the case the user recovers it. When the credential is deleted, it goes away forever.

* **Can a user delete its credentials from its device?**

Yes. If it does, the other part of the credentials in your server gets virtually orphaned. You may want to show the user a list of registered credentials to delete them.

* **How secure is this against passwords or 2FA?**

Extremely secure since it works only on HTTPS (or `localhost`), and no password are exchanged, or codes are visible in the screen.

* **Can I deactivate the password fallback? Can I enforce only WebAuthn authentication?**

Yes. Just be sure to [use the recovery helpers](#6-set-up-account-recovery-optional) to avoid locking out your users..

* **Does this includes a frontend Javascript?**

[Yes](#5-use-the-javascript-helper-optional), but it's very _basic_. 

* **Does this encodes/decode the strings automatically in the frontend?**

Yes, the included [WebAuthn Helper](#5-use-the-javascript-helper-optional) does it automatically for you.

* **Does this include a credential recovery routes?**

[Yes.](#6-set-up-account-recovery-optional)

* **Can I use my smartphone as authenticator through a PC desktop/laptop/terminal?**

Depends on the OS and hardware. Some will require previously pairing the device to an "account". Others  will only work with USB keys. This is up to hardware and software vendor themselves.

* **Why my device doesn't show Windows Hello/TouchId/FaceId/fingerprint authentication?**

By default, this WebAuthn implementation accepts almost everything. Some combinations of devices, OS and web browsers may differ on what to make available for WebAuthn authentication. In other words, it's not my fault.

* **I'm trying to test this in my development server but it doesn't work**

Use `localhost` exclusively, or use [ngrok](https://ngrok.com/) (or similar) to tunnel your site through HTTPS. WebAuthn only works on `localhost` or `HTTPS` only.

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.

Laravel is a Trademark of Taylor Otwell. Copyright © 2011-2020 Laravel LLC.

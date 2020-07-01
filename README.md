![Lukenn Sabellano - Unsplash (UL) #RDufjtg6JpQ](https://images.unsplash.com/photo-1567826722186-9ecdf689f122?ixlib=rb-1.2.1&auto=format&fit=crop&w=1280&h=400&q=80)

[![Latest Stable Version](https://poser.pugx.org/darkghosthunter/larapass/v/stable)](https://packagist.org/packages/darkghosthunter/larapass) [![License](https://poser.pugx.org/darkghosthunter/larapass/license)](https://packagist.org/packages/darkghosthunter/larapass)
![](https://img.shields.io/packagist/php-v/darkghosthunter/larapass.svg)
 ![](https://github.com/DarkGhostHunter/Larapass/workflows/PHP%20Composer/badge.svg) [![Coverage Status](https://coveralls.io/repos/github/DarkGhostHunter/Larapass/badge.svg?branch=master)](https://coveralls.io/github/DarkGhostHunter/Larapass?branch=master)

## Larapass

Authenticate users with just their device, fingerprint or biometric data. Goodbye passwords!

This enables WebAuthn authentication using Laravel authentication driver.

## Requisites

* PHP 7.2.15+
* Laravel 7

## What is WebAuthn? How it uses fingerprints or else?

In a nutshell, [mayor browsers are compatible with Web Authentication API](https://caniuse.com/#feat=webauthn), pushing authentication to the device (fingerprints, Face ID, patterns, codes, etc) instead of plain-text passwords.

This package validates authentication responses from the devices using a custom [user provider](https://laravel.com/docs/authentication#adding-custom-user-providers).

If you have any doubts about WebAuthn, [check this small FAQ](#faq).

## Installation

1. Add the `eloquent-webauthn` driver to your authentication configuration in `config/auth.php`.
2. Migrate the `webauthn_credentials` table.
3. Implement the `WebAuthnAuthenticatable` contract and `WebAuthnAuthentication` trait to your User(s) classes.

### 1. Add the `eloquent-webauthn` driver.

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

Create the `webauthn_credentials` table by running the migrations:

    php artisan migrate

> If you need to modify the migration from this package, you can publish it to override whatever you need.
>
>     php artisan vendor:publish --provider="DarkGhostHunter\Larapass\LarapassServiceProvider" --tag="migrations"

### 3. Add the WebAuthn contract and trait

Add the `WebAuthnAuthenticatable` contract and the `WebAuthnAuthentication` trait to the `Authenticatable` user class, or any that uses authentication.

```php
<?php

use Illuminate\Foundation\Auth\User as Authenticatable;
use DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable;
use DarkGhostHunter\Larapass\WebAuthnAuthentication;

class User extends Authenticatable implements WebAuthnAuthenticatable
{
    use WebAuthnAuthentication;

    // ...
}
```

> The trait is used to basically tie the User model to the WebAuthn data contained in the database.

### 4. Register the routes

Finally, you will need to add the routes for registering and authenticating users. If you want a quick start, just publish the controllers included in Larapass.

    php artisan vendor:publish --provider="DarkGhostHunter\Larapass\LarapassServiceProvider" --tag="controllers"
 
You can copy-paste these route definitions in your `routes/web.php` file. 

```php
Route::post('webauthn/register/options', 'Auth\WebAuthnRegisterController@options')
    ->name('webauthn.register.options');
Route::post('webauthn/register', 'Auth\WebAuthnRegisterController@register')
    ->name('webauthn.register');

Route::post('webauthn/login/options', 'Auth\WebAuthnLoginController@options')
    ->name('webauthn.login.options');
Route::post('webauthn/login', 'Auth\WebAuthnLoginController@login')
    ->name('webauthn.login');
```

In your frontend scripts, point the requests to these routes.

> If you want full control, you can opt-out of these helper controllers and use your own logic. Use the [`AttestWebAuthn`](src/Http/AttestsWebAuthn.php) and [`AssertsWebAuthn`](src/Http/AssertsWebAuthn.php) traits if you need to start with something.

## Frontend integration

You're in charge of registering and authenticating users as you want using your own scripts in your frontend. **Larapass doesn't include scripts** because there is no best all-around script that cover all use cases (Vue.js, React.js, vanilla Javascript, etc).

The important bit is to point the _attest_ (registration) and _assert_ (login) to the routes used for each of them.

If you want to start with something, I recommend these [WebAuthn Javascript Helpers](https://github.com/web-auth/webauthn-helper) which are simple and straightforward.

```javascript
import {useLogin} from 'webauthn-helper';

const login = useLogin({
    loginOptions: '/webauthn/login/options',
    loginUrl:     '/webauthn/login',
});

login({
    username: 'John Doe'
})
    .then(response => window.location.replace = 'https://myapp.com/welcome')
    .catch(error => console.log(error));
```

## Events

Since all authentication is handled by Laravel itself, the only [event](https://laravel.com/docs/events) included is [`AttestationSuccessful`](src/Events/AttestationSuccessful.php), which fires when the registration is successful. It includes the user and the credentials persisted.

You can use this event to, for example, notify the user a new device has been registered and with what ID. For that, you can use a [listener](https://laravel.com/docs/events#defining-listeners).

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

$email = request()->input('email');

$user = User::where('email', $email)->firstOrFail();

// Create an assertion for the given user.
return WebAuthn::generateAssertion($user);
```

Then later we can verify it:

```php
<?php

use App\User;
use Illuminate\Support\Facades\Auth;
use DarkGhostHunter\Larapass\Facades\WebAuthn;

$credentialId = request()->json('id');

// Get the user using the credential ID.
$user = User::getFromCredentialId($credentialId);

// Verify it
$isValid = WebAuthn::validateAssertion(
    request()->json()->all(), $user
);

// If is valid, login the user
if ($isValid) {
    Auth::login($user);
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
        'name' => env('WEBAUTHN_NAME', env('APP_NAME', 'Laravel')),
        'id'   => env('WEBAUTHN_ID'),
        'icon' => env('WEBAUTHN_ICON'),
    ],
    'bytes' => 16,
    'timeout' => 60,
    'cache' => env('WEBAUTHN_CACHE'),
    'algorithms' => [
        -7,
        -8,
        -35,
        -36,
        -257,
    ],
    'attachment' => null,
    'conveyance' => 'none',
    'login_verify' => true,
    'userless' => null,
    'fallback' => true,
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
        -7,    // ECDSA with SHA-256
        -8,    // EdDSA
        -35,   // ECDSA with SHA-384
        -36,   // ECDSA with SHA-512
        -257,  // RSASSA-PKCS1-v1_5 with SHA-256
    ],
];
```

This controls how the authenticator (device) will operate to create the public-private keys. These [COSE Algorithms](https://w3c.github.io/webauthn/#typedefdef-cosealgorithmidentifier) are the most compatible ones for in-device and roaming keys, since some must be transmitted on low bandwidth protocols.

> Leave as it is, unless you know what you're doing.

### Key Attachment

```php
return [
     'attachment' => null,
];
```

By default, the user decides what to use to register. If you wish to exclusively use a cross-platform authentication (like USB Keys, CA Servers or Certificates) set this to `true`, or `false` if you want to enforce device-only authentication. 

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
    'login_verify' => true,
];
```

By default, the application will require the user to log in by confirming with biometrics, PIN or patterns in his device.

You can disable this verification to only check for user presence (like a "Continue" button), which may make the login faster but making it slightly less secure.

> When setting [userless](#userless-login-one-touch-typeless) as `preferred` or `required`, this will be overridden to `true`.

### Userless login (One touch, Typeless)

```php
return [
    'userless' => null,
];
```

You can activate _userless_ login, also known as one-touch login or typless login. You should change this to `preferred` in that case, since not all devices support the feature.

If this is activated (not `null` or `discouraged`), login verification will be mandatory.

### Password Fallback

```php
return [
    'fallback' => true,
];
```

By default, this package allows to re-use the same `eloquent-webauthn` driver to log in users with passwords when the credentials are not a WebAuthn.

Disabling the fallback will only check for WebAuthn credentials. To handle classic user/password scenarios, you should create a separate guard.

## Remembering Users

You can enable it by just issuing the `WebAuthn-Remember` header value to `true` when pushing the signed login challenge from your frontend, or adding the `remember` key to the JSON Payload if you're able to.

```javascript
fetch('/webauthn/login', {
  method: 'POST',
  credentials: 'same-origin',
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'WebAuthn-Remember': true,
  },
  body: JSON.stringify(publicKeyCredentialsSource),
})
```

> You can override this in the [`AssertsWebAuthn`](src/Http/AssertsWebAuthn.php) trait.

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

1. Registration (attestation) is remembered by user, domain and IP.
2. Login (assertion) is remembered by domain and IP.
3. Cached challenge is always forgotten after resolution, independently of the result.
4. Cached challenge TTL is the same as the WebAuthn timeout (60 seconds default).
5. Included controllers include throttling for WebAuthn endpoints.
6. Users ID (handle) is a random UUID v4.
7. Credentials can be blacklisted (enabled/disabled).

If you discover any security related issues, please email darkghosthunter@gmail.com instead of using the issue tracker.

> As a sidenote, remember to [configure your application properly if it's behind a load balancer](https://laravel.com/docs/requests#configuring-trusted-proxies).

## FAQ

* **Does this work with any browser?**

[Yes](https://caniuse.com/#feat=webauthn). In the case of old browsers, you should have a fallback detection script:

```javascript
if (typeof(PublicKeyCredential) == "undefined") {
   alert('Your device is not secure enough to use this site!');
}
```

* **Does this stores the user's fingerprint, PIN or patterns in my site?**

No.

* **Can a phishing site steal WebAuthn credentials and use them in my site?**

No. WebAuthn kills phishing.

* **Can the WebAuthn data identify a particular device?**

Not, unless explicitly requested and consented.

* **Are my user's classic passwords safe?**

Yes, as long you are hashing them as you should, and you have secured your application key. This is done by Laravel by default. You can also [disable them](#password-fallback).

* **Can a user register two or more _devices_?**

Yes, but you need to manually attest (register) these.

* **What happens if a credential is cloned?**

The user won't be authenticated since the server counter will be greater than the reported by the credential. To detect it, modify the Assertion Validator in the Service Container and add your own `CounterChecker`:

```php
<?php

namespace App\WebAuthn;

use App\User;
use Webauthn\Counter\CounterChecker;
use App\Notifications\CredentialCloned;
use Webauthn\PublicKeyCredentialSource;

class MyCountChecker implements CounterChecker
{
    public function check(PublicKeyCredentialSource $credentials, 
                          int $currentCounter) : void
    {
        if ($credentials->getCounter() <= $currentCounter) {
            $credentialId = $credentials->getPublicKeyCredentialId();

            User::getFromCredentialId($credentialId)->notify(new CredentialCloned($credentialId));
        }
    }
}
```

* **If a user loses his device, can he register a new device?**

Yes, just send him a signed email to register a new device with secure attestation and assertion routes. That's up to you.

> To blacklist a device, use `disableDevice()` in the user instance.

* **How secure is this against passwords or 2FA?**

Extremely secure since it works only on HTTPS, and no password or codes are exchanged after registration.

* **Can I deactivate the password fallback? Can I enforce only WebAuthn authentication?**

Yes. Just be sure to disable the password column in the users table, the Password Broker, and have some logic to register new devices and invalidate old ones. The [`WebAuthnAuthentication`](src/WebAuthnAuthentication.php) trait helps with this.

* **Does this includes Javascript?**

No, mainly because each application frontend is different. A given script may not work for you.

* **Does this encodes/decode the strings automatically in the frontend?**

No, you must ensure to encode/decode to binary forms some strings in your frontend because the nature of WebAuthn. This [WebAuthn Javascript Helpers](https://github.com/web-auth/webauthn-helper) package does it automatically for you.

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.

Laravel is a Trademark of Taylor Otwell. Copyright © 2011-2020 Laravel LLC.

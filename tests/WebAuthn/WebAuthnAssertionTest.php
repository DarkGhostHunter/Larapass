<?php

namespace Tests\WebAuthn;

use Base64Url\Base64Url;
use DarkGhostHunter\Larapass\WebAuthn\WebAuthnAssertValidator;
use Exception;
use Illuminate\Cache\Repository;
use Illuminate\Contracts\Cache\Factory as CacheFactoryContract;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Mockery;
use Orchestra\Testbench\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Ramsey\Uuid\Uuid;
use Tests\RegistersPackage;
use Tests\RunsPublishableMigrations;
use Tests\Stubs\TestWebAuthnUser;
use Webauthn\AttestedCredentialData;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorResponse;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\TrustPath\EmptyTrustPath;

class WebAuthnAssertionTest extends TestCase
{
    use RegistersPackage,
        RunsPublishableMigrations;

    /** @var \Tests\Stubs\TestWebAuthnUser */
    protected $user;

    protected function setUp() : void
    {
        $this->afterApplicationCreated(function () {
            $this->loadLaravelMigrations();
            $this->loadMigrationsFrom([
                '--realpath' => true,
                '--path'     => [
                    realpath(__DIR__ . '/../../database/migrations'),
                ],
            ]);

            $this->user = TestWebAuthnUser::make()->forceFill([
                'name'     => 'john',
                'email'    => 'john.doe@mail.com',
                'password' => '$2y$10$FLIykVJWDsYSVMJyaFZZfe4tF5uBTnGsosJBL.ZfAAHsYgc27FSdi',
            ]);

            DB::table('web_authn_credentials')->insert([
                'id'               => 'test_credential_foo',
                'user_id'          => 1,
                'type'             => 'public_key',
                'transports'       => json_encode([]),
                'attestation_type' => 'none',
                'trust_path'       => json_encode(['type' => EmptyTrustPath::class]),
                'aaguid'           => Str::uuid(),
                'public_key'       => 'public_key_foo',
                'counter'          => 0,
                'user_handle'      => Str::uuid()->toString(),
                'created_at'       => now()->toDateTimeString(),
                'updated_at'       => now()->toDateTimeString(),
            ]);

            $this->user->save();
        });

        parent::setUp();
    }

    public function test_creates_new_assert_for_user()
    {
        $result = $this->app[WebAuthnAssertValidator::class]->generateAssertion($this->user);

        $this->assertInstanceOf(PublicKeyCredentialRequestOptions::class, $result);

        $firstCredential = Arr::first($result->getAllowCredentials());

        $this->assertSame('public_key', $firstCredential->getType());
        $this->assertSame('test_credential_foo', Base64Url::encode($firstCredential->getId()));
        $this->assertCount(0, $result->getExtensions());
        $this->assertSame(60000, $result->getTimeout());
        $this->assertSame('preferred', $result->getUserVerification());
        $this->assertNull($result->getRpId());
    }

    public function test_assertions_never_are_the_same()
    {
        $first = $this->app[WebAuthnAssertValidator::class]->generateAssertion($this->user);
        $second = $this->app[WebAuthnAssertValidator::class]->generateAssertion($this->user);

        $this->assertNotSame($first->getChallenge(), $second->getChallenge());
    }

    public function test_creates_blank_assertion()
    {
        $result = $this->app[WebAuthnAssertValidator::class]->generateAssertion();

        $this->assertInstanceOf(PublicKeyCredentialRequestOptions::class, $result);
        $this->assertEmpty($result->getAllowCredentials());
    }

    public function test_creates_different_challenges_on_blank_assertion()
    {
        $first = $this->app[WebAuthnAssertValidator::class]->generateAssertion();
        $second = $this->app[WebAuthnAssertValidator::class]->generateAssertion();

        $this->assertNotSame($first->getChallenge(), $second->getChallenge());
    }

    public function test_creates_with_verification_overridden_by_userless()
    {
        $this->app['config']->set('larapass.login_verify', false);

        $this->app['config']->set('larapass.userless', 'required');

        $request = $this->app[WebAuthnAssertValidator::class]->generateAssertion();

        $this->assertSame('required', $request->getUserVerification());

        $this->app['config']->set('larapass.userless', 'preferred');

        $request = $this->app[WebAuthnAssertValidator::class]->generateAssertion();

        $this->assertSame('required', $request->getUserVerification());
    }

    public function test_assert_validates_and_returns_credentials()
    {
        Route::get('something', function () {
            return response()->noContent();
        });

        $this->get('something')->assertNoContent();

        $request = $this->mock(Request::class);
        $request->shouldReceive('getHttpHost')->andReturn('test_host');
        $request->shouldReceive('ip')->andReturn('127.0.0.1');

        $cache = $this->mock(Repository::class);

        $cache->shouldReceive('forget');
        $options = new PublicKeyCredentialRequestOptions(
            random_bytes(16),
            60000);
        $options->setRpId('test_id')->allowCredentials([])->setUserVerification($options::USER_VERIFICATION_REQUIREMENT_REQUIRED);
        $cache->shouldReceive('get')->andReturn($options);

        $this->mock(CacheFactoryContract::class)
            ->shouldReceive('store')
            ->with(null)
            ->andReturn($cache);

        /** @var AuthenticatorAssertionResponse */
        $response = Mockery::mock(AuthenticatorAssertionResponse::class);

        $credential = new PublicKeyCredential(
            'test_credential_id',
            'public-key',
            'a04f39f8ba6a4a19b98a0579bf76505ea6d55730745274616166ef827b649506',
            $response
        );

        $this->mock(PublicKeyCredentialLoader::class)
            ->shouldReceive('loadArray')
            ->with(['foo' => 'bar'])
            ->andReturn($credential);

        $response->shouldReceive('getUserHandle')
            ->once()
            ->andReturn($handle = $this->user->userEntity()->getId());

        $this->mock(AuthenticatorAssertionResponseValidator::class)
            ->shouldReceive('check')
            ->with(
                'a04f39f8ba6a4a19b98a0579bf76505ea6d55730745274616166ef827b649506',
                $response,
                $options,
                Mockery::type(ServerRequestInterface::class),
                $handle,
                [0 => 'test_id']
            )
            ->once()
            ->andReturn($this->user->webAuthnCredentials()->first()->toCredentialSource());

        $result = $this->app[WebAuthnAssertValidator::class]->validate(['foo' => 'bar']);

        $this->assertInstanceOf(PublicKeyCredentialSource::class, $result);
    }

    public function test_assert_fails_when_check_fails()
    {
        Route::get('something', function () {
            return response()->noContent();
        });

        $this->get('something')->assertNoContent();

        $request = $this->mock(Request::class);
        $request->shouldReceive('getHttpHost')->andReturn('test_host');
        $request->shouldReceive('ip')->andReturn('127.0.0.1');

        $cache = $this->mock(Repository::class);

        $cache->shouldReceive('forget');
        $options = new PublicKeyCredentialRequestOptions(
            random_bytes(16),
            60000);
        $options->setRpId('test_id')->allowCredentials([])->setUserVerification($options::USER_VERIFICATION_REQUIREMENT_REQUIRED);
        $cache->shouldReceive('get')->andReturn($options);

        $this->mock(CacheFactoryContract::class)
            ->shouldReceive('store')
            ->with(null)
            ->andReturn($cache);

        /** @var AuthenticatorAssertionResponse */
        $response = Mockery::mock(AuthenticatorAssertionResponse::class);

        $credential = new PublicKeyCredential(
            'test_credential_id',
            'public-key',
            'a04f39f8ba6a4a19b98a0579bf76505ea6d55730745274616166ef827b649506',
            $response
        );

        $this->mock(PublicKeyCredentialLoader::class)
            ->shouldReceive('loadArray')
            ->with(['foo' => 'bar'])
            ->andReturn($credential);

        $response->shouldReceive('getUserHandle')
            ->once()
            ->andReturn($handle = $this->user->userEntity()->getId());

        $this->mock(AuthenticatorAssertionResponseValidator::class)
            ->shouldReceive('check')
            ->with(
                'a04f39f8ba6a4a19b98a0579bf76505ea6d55730745274616166ef827b649506',
                $response,
                $options,
                Mockery::type(ServerRequestInterface::class),
                $handle,
                [0 => 'test_id']
            )
            ->once()
            ->andThrow(new InvalidArgumentException);

        $result = $this->app[WebAuthnAssertValidator::class]->validate(['foo' => 'bar']);

        $this->assertFalse($result);
    }

    public function test_assert_fails_if_no_previous_assert_was_generated()
    {
        Route::get('something', function () {
            return response()->noContent();
        });

        $this->get('something')->assertNoContent();

        $request = $this->mock(Request::class);
        $request->shouldReceive('getHttpHost')->andReturn('test_host');
        $request->shouldReceive('ip')->andReturn('127.0.0.1');

        $cache = $this->mock(Repository::class);

        $cache->shouldReceive('forget');
        $cache->shouldReceive('get')->andReturnNull();

        $this->mock(CacheFactoryContract::class)
            ->shouldReceive('store')
            ->with(null)
            ->andReturn($cache);

        $this->mock(PublicKeyCredentialLoader::class)
            ->shouldNotReceive('loadArray');

        $this->mock(AuthenticatorAssertionResponseValidator::class)
            ->shouldNotReceive('check');

        $result = $this->app[WebAuthnAssertValidator::class]->validate(['foo' => 'bar']);

        $this->assertFalse($result);
    }

    public function test_assert_fails_if_response_incorrect()
    {
        Route::get('something', function () {
            return response()->noContent();
        });

        $this->get('something')->assertNoContent();

        $request = $this->mock(Request::class);
        $request->shouldReceive('getHttpHost')->andReturn('test_host');
        $request->shouldReceive('ip')->andReturn('127.0.0.1');

        $cache = $this->mock(Repository::class);

        $cache->shouldReceive('forget');
        $options = new PublicKeyCredentialRequestOptions(
            random_bytes(16),
            60000);
        $options->setRpId('test_id')->allowCredentials([])->setUserVerification($options::USER_VERIFICATION_REQUIREMENT_REQUIRED);
        $cache->shouldReceive('get')->andReturn($options);

        $this->mock(CacheFactoryContract::class)
            ->shouldReceive('store')
            ->with(null)
            ->andReturn($cache);

        /** @var PublicKeyCredential */
        $credential = Mockery::mock(PublicKeyCredential::class);
        $credential->shouldReceive('getResponse')
            ->andReturn(new class extends AuthenticatorResponse {
                public function __construct()
                {
                }
            });

        $this->mock(PublicKeyCredentialLoader::class)
            ->shouldReceive('loadArray')
            ->with(['foo' => 'bar'])
            ->andReturn($credential);

        $this->mock(AuthenticatorAssertionResponseValidator::class)
            ->shouldNotReceive('check');

        $result = $this->app[WebAuthnAssertValidator::class]->validate(['foo' => 'bar']);

        $this->assertFalse($result);
    }

    public function test_assert_fails_when_validator_throws_exception()
    {
        Route::get('something', function () {
            return response()->noContent();
        });

        $this->get('something')->assertNoContent();

        $request = $this->mock(Request::class);
        $request->shouldReceive('getHttpHost')->andReturn('test_host');
        $request->shouldReceive('ip')->andReturn('127.0.0.1');

        $cache = $this->mock(Repository::class);

        $cache->shouldReceive('forget');
        $options = new PublicKeyCredentialRequestOptions(
            random_bytes(16),
            60000);
        $options->setRpId('test_id')->allowCredentials([])->setUserVerification($options::USER_VERIFICATION_REQUIREMENT_REQUIRED);
        $cache->shouldReceive('get')->andReturn($options);

        $this->mock(CacheFactoryContract::class)
            ->shouldReceive('store')
            ->with(null)
            ->andReturn($cache);

        /** @var AuthenticatorAssertionResponse */
        $response = Mockery::mock(AuthenticatorAssertionResponse::class);

        $credential = new PublicKeyCredential(
            'test_credential_id',
            'public-key',
            'a04f39f8ba6a4a19b98a0579bf76505ea6d55730745274616166ef827b649506',
            $response
        );

        $this->mock(PublicKeyCredentialLoader::class)
            ->shouldReceive('loadArray')
            ->with(['foo' => 'bar'])
            ->andReturn($credential);

        $response->shouldReceive('getUserHandle')
            ->once()
            ->andReturn($handle = $this->user->userEntity()->getId());

        $this->mock(AuthenticatorAssertionResponseValidator::class)
            ->shouldReceive('check')
            ->with(
                'a04f39f8ba6a4a19b98a0579bf76505ea6d55730745274616166ef827b649506',
                $response,
                $options,
                Mockery::type(ServerRequestInterface::class),
                $handle,
                [0 => 'test_id']
            )
            ->once()
            ->andThrow(new InvalidArgumentException);

        $result = $this->app[WebAuthnAssertValidator::class]->validate(['foo' => 'bar']);

        $this->assertFalse($result);
    }

    public function test_assert_fails_when_throws_exception()
    {
        $this->expectException(Exception::class);

        Route::get('something', function () {
            return response()->noContent();
        });

        $this->get('something')->assertNoContent();

        $request = $this->mock(Request::class);
        $request->shouldReceive('getHttpHost')->andReturn('test_host');
        $request->shouldReceive('ip')->andReturn('127.0.0.1');

        $cache = $this->mock(Repository::class);

        $cache->shouldReceive('forget');
        $options = new PublicKeyCredentialRequestOptions(
            random_bytes(16),
            60000);
        $options->setRpId('test_id')->allowCredentials([])->setUserVerification($options::USER_VERIFICATION_REQUIREMENT_REQUIRED);
        $cache->shouldReceive('get')->andReturn($options);

        $this->mock(CacheFactoryContract::class)
            ->shouldReceive('store')
            ->with(null)
            ->andReturn($cache);

        $response = Mockery::mock(AuthenticatorAssertionResponse::class);

        /** @var AuthenticatorAssertionResponse */
        $credential = new PublicKeyCredential(
            'test_credential_id',
            'public-key',
            'a04f39f8ba6a4a19b98a0579bf76505ea6d55730745274616166ef827b649506',
            $response
        );

        $this->mock(PublicKeyCredentialLoader::class)
            ->shouldReceive('loadArray')
            ->with(['foo' => 'bar'])
            ->andReturn($credential);

        $response->shouldReceive('getUserHandle')
            ->once()
            ->andReturn($handle = $this->user->userEntity()->getId());

        $this->mock(AuthenticatorAssertionResponseValidator::class)
            ->shouldReceive('check')
            ->with(
                'a04f39f8ba6a4a19b98a0579bf76505ea6d55730745274616166ef827b649506',
                $response,
                $options,
                Mockery::type(ServerRequestInterface::class),
                $handle,
                [0 => 'test_id']
            )
            ->once()
            ->andThrow(new Exception);

        $this->app[WebAuthnAssertValidator::class]->validate(['foo' => 'bar']);
    }

    public function test_attestation_reaches_repository()
    {
        Route::get('something', function () {
            return response()->noContent();
        });

        $this->get('something')->assertNoContent();

        $cache = $this->mock(Repository::class);

        $cache->shouldReceive('forget');
        $options = new PublicKeyCredentialRequestOptions(
            base64_decode('w+BeaUTZZnYMzvUB5GWUpiT1WYOnr9iCGUt5irUiUko='),
            60000);
        $options->setRpId('webauthn.spomky-labs.com')->allowCredentials([]);
        $cache->shouldReceive('get')->andReturn($options);

        $this->mock(CacheFactoryContract::class)
            ->shouldReceive('store')
            ->with(null)
            ->andReturn($cache);

        $source = $this->mock(PublicKeyCredentialSource::class);

        $source->shouldReceive('getUserHandle')
            ->andReturn('ee13d4f1-4863-47dd-a407-097cb49ac822');
        $source->shouldReceive('getCounter')
            ->andReturn(0);
        $source->shouldReceive('setCounter')
            ->with(4)
            ->andReturnNull();
        $source->shouldReceive('getAttestedCredentialData')
            ->andReturn(
                new AttestedCredentialData(
                    Uuid::fromBytes(base64_decode('YCiwF7HUTAK0s6/Nr8lrsg==', true)),
                    base64_decode('6oRgydKXdC3LtZBDoAXxKnWte68elEQejDrYOV9x+18=', true),
                    base64_decode('pAEDAzkBACBZAQDwn2Ee7V+9GNDn2iCU2plQnIVmZG/vOiXSHb9TQzC5806bGzLV918+1SLFhMhlX5jua2rdXt65nYw9Eln7mbmVxLBDmEm2wod6wP2HinC9HPsYwr75tMRakLMNFfH4Xx4lEsjulRmv68yl/N8XH64X8LKe2GBxjqcuJR+c3LbW4D5dWt/1pGL8fS1UbO3abA/d3IeEsP8RpEz5eVo6qBhb4r0VTo2NMeq75saBHIj4whqo6qsRqRvBmK2d9NAecBFFRIQ31NUtEQZPqXOzkbXGehDi7c3YJPBkTW9kMqcosob9Vlru+vVab+1PnFRdqaklR1UtmhrWte/wB61Hm3xdIUMBAAE=', true)
                )
            );
        $source->shouldReceive('jsonSerialize')
            ->andReturn(['foo' => 'bar']);

        $repo = $this->mock(PublicKeyCredentialSourceRepository::class);

        $repo->shouldReceive('findOneByCredentialId')
            ->with(base64_decode('6oRgydKXdC3LtZBDoAXxKnWte68elEQejDrYOV9x+18=', true))
            ->andReturn($source);

        $repo->shouldReceive('saveCredentialSource')
            ->with($source)
            ->andReturnNull();

        $credential = $this->app[WebAuthnAssertValidator::class]->validate([
            'id'       => '6oRgydKXdC3LtZBDoAXxKnWte68elEQejDrYOV9x-18',
            'type'     => 'public-key',
            'rawId'    => '6oRgydKXdC3LtZBDoAXxKnWte68elEQejDrYOV9x+18=',
            'response' => [
                'authenticatorData' => 'lgTqgoJOmKStoUtEYtDXOo7EaRMNqRsZMHRZIp90o1kFAAAABA==',
                'clientDataJSON'    => 'ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5nZXQiLA0KCSJjaGFsbGVuZ2UiIDogInctQmVhVVRaWm5ZTXp2VUI1R1dVcGlUMVdZT25yOWlDR1V0NWlyVWlVa28iLA0KCSJvcmlnaW4iIDogImh0dHBzOi8vd2ViYXV0aG4uc3BvbWt5LWxhYnMuY29tIiwNCgkidG9rZW5CaW5kaW5nIiA6IA0KCXsNCgkJInN0YXR1cyIgOiAic3VwcG9ydGVkIg0KCX0NCn0=',
                'signature'         => 'lV7pKH+0rVaaWC5ZoQIMSW1EjeIELfUTKcplaSW65I8rH7U38qVoTYyvxQiZwtQsqKgXOMQYJ6n1JV+is3yi8wOjxkkmR/bLPPssLz7Za1ooSAJ+R1JKTYsmsozpTmouCVtBN4Il92Zrhy9sOD3pVUjHUJaXaEsV2dReqEamwt9+VLQiD0fJwYrqiyWETEybGqJSj7p2Zb0BVOcevlPCj3tX84DreZMW7lkYE6PyuJCmi7eR/kKq2N+ohvH6H3aHloQ+kgSb2L2gJn1hjs5Z3JxMvrwmnj0Vx1J2AMWrQyuBeBblJN3UP3Wbk16e+8Bq8HC9W6JG9qgqTyR1wJx0Yw==',
                'userHandle'        => 'ZWUxM2Q0ZjEtNDg2My00N2RkLWE0MDctMDk3Y2I0OWFjODIy',
            ],
        ]);

        $this->assertInstanceOf(PublicKeyCredentialSource::class, $credential);
    }
}

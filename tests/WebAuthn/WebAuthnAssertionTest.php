<?php

namespace Tests\WebAuthn;

use Mockery;
use Exception;
use Tests\RegistersPackage;
use Illuminate\Support\Str;
use Illuminate\Support\Arr;
use Illuminate\Http\Request;
use InvalidArgumentException;
use Illuminate\Cache\Repository;
use Orchestra\Testbench\TestCase;
use Tests\Stubs\TestWebAuthnUser;
use Webauthn\PublicKeyCredential;
use Illuminate\Support\Facades\DB;
use Webauthn\AuthenticatorResponse;
use Tests\RunsPublishableMigrations;
use Illuminate\Support\Facades\Route;
use Webauthn\TrustPath\EmptyTrustPath;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\AuthenticatorAssertionResponse;
use Psr\Http\Message\ServerRequestInterface;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\AuthenticatorAssertionResponseValidator;
use DarkGhostHunter\Larapass\Exceptions\WebAuthnException;
use Illuminate\Contracts\Cache\Factory as CacheFactoryContract;
use DarkGhostHunter\Larapass\WebAuthn\WebAuthnAssertValidator;

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
                'credential_id'         => 'test_credential_foo',
                'user_id'               => 1,
                'is_enabled'            => true,
                'type'                  => 'public_key',
                'transports'            => json_encode([]),
                'attestation_type'      => 'none',
                'trust_path'            => json_encode(['type' => EmptyTrustPath::class]),
                'aaguid'                => Str::uuid(),
                'credential_public_key' => 'public_key_foo',
                'counter'               => 0,
                'user_handle'           => Str::uuid()->toString(),
                'created_at'            => now()->toDateTimeString(),
                'updated_at'            => now()->toDateTimeString(),
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
        $this->assertSame('test_credential_foo', $firstCredential->getId());
        $this->assertCount(0, $result->getExtensions());
        $this->assertSame(60000, $result->getTimeout());
        $this->assertSame('1', $result->getUserVerification());
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

        $this->assertSame('1', $request->getUserVerification());

        $this->app['config']->set('larapass.userless', 'preferred');

        $request = $this->app[WebAuthnAssertValidator::class]->generateAssertion();

        $this->assertSame('1', $request->getUserVerification());
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
        $cache->shouldReceive('get')->andReturn(
            $options = new PublicKeyCredentialRequestOptions(
                random_bytes(16),
                60000,
                'test_id',
                [],
                true
            )
        );

        $this->mock(CacheFactoryContract::class)
            ->shouldReceive('store')
            ->with(null)
            ->andReturn($cache);

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
                'test_credential_id',
                $response,
                $options,
                Mockery::type(ServerRequestInterface::class),
                $handle
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
        $cache->shouldReceive('get')->andReturn(
            $options = new PublicKeyCredentialRequestOptions(
                random_bytes(16),
                60000,
                'test_id',
                [],
                true
            )
        );

        $this->mock(CacheFactoryContract::class)
            ->shouldReceive('store')
            ->with(null)
            ->andReturn($cache);

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
                'test_credential_id',
                $response,
                $options,
                Mockery::type(ServerRequestInterface::class),
                $handle
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
        $cache->shouldReceive('get')->andReturn(
            $options = new PublicKeyCredentialRequestOptions(
                random_bytes(16),
                60000,
                'test_id',
                [],
                true
            )
        );

        $this->mock(CacheFactoryContract::class)
            ->shouldReceive('store')
            ->with(null)
            ->andReturn($cache);

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
        $cache->shouldReceive('get')->andReturn(
            $options = new PublicKeyCredentialRequestOptions(
                random_bytes(16),
                60000,
                'test_id',
                [],
                true
            )
        );

        $this->mock(CacheFactoryContract::class)
            ->shouldReceive('store')
            ->with(null)
            ->andReturn($cache);

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
                'test_credential_id',
                $response,
                $options,
                Mockery::type(ServerRequestInterface::class),
                $handle
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
        $cache->shouldReceive('get')->andReturn(
            $options = new PublicKeyCredentialRequestOptions(
                random_bytes(16),
                60000,
                'test_id',
                [],
                true
            )
        );

        $this->mock(CacheFactoryContract::class)
            ->shouldReceive('store')
            ->with(null)
            ->andReturn($cache);

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
                'test_credential_id',
                $response,
                $options,
                Mockery::type(ServerRequestInterface::class),
                $handle
            )
            ->once()
            ->andThrow(new Exception);

        $this->app[WebAuthnAssertValidator::class]->validate(['foo' => 'bar']);
    }
}
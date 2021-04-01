<?php

namespace Tests\WebAuthn;

use Base64Url\Base64Url;
use DarkGhostHunter\Larapass\WebAuthn\AuthenticatorSelectionCriteria;
use DarkGhostHunter\Larapass\WebAuthn\PublicKeyCredentialParametersCollection;
use DarkGhostHunter\Larapass\WebAuthn\WebAuthnAttestCreator;
use DarkGhostHunter\Larapass\WebAuthn\WebAuthnAttestValidator;
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
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorResponse;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\TrustPath\EmptyTrustPath;

class WebAuthnAttestationTest extends TestCase
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
                'id'         => 'test_credential_foo',
                'user_id'               => 1,
                'type'                  => 'public_key',
                'transports'            => json_encode([]),
                'attestation_type'      => 'none',
                'trust_path'            => json_encode(['type' => EmptyTrustPath::class]),
                'aaguid'                => Str::uuid(),
                'public_key' => 'public_key_foo',
                'counter'               => 0,
                'user_handle'           => Str::uuid()->toString(),
                'created_at'            => now()->toDateTimeString(),
                'updated_at'            => now()->toDateTimeString(),
            ]);

            $this->user->save();
        });

        parent::setUp();
    }

    public function test_generates_new_attestation()
    {
        Route::get('something', function () {
            return response()->noContent();
        });

        $this->get('something')->assertNoContent();

        $request = $this->mock(Request::class);

        $request->shouldReceive('getHttpHost')
            ->andReturn('test_host');

        $request->shouldReceive('ip')
            ->andReturn('127.0.0.1');

        $attestation = $this->app[WebAuthnAttestCreator::class]->generateAttestation($this->user);

        $this->assertInstanceOf(PublicKeyCredentialCreationOptions::class, $attestation);

        $this->assertNull($attestation->getRp()->getId());
        $this->assertNull($attestation->getRp()->getIcon());
        $this->assertSame('Laravel', $attestation->getRp()->getName());

        $this->assertSame(
            $this->user->webAuthnCredentials()->value('user_handle'),
            $attestation->getUser()->getId()
        );

        $this->assertSame('john.doe@mail.com', $attestation->getUser()->getName());
        $this->assertSame('john', $attestation->getUser()->getDisplayName());
        $this->assertNull($attestation->getUser()->getIcon());

        $this->assertCount(5, $attestation->getPubKeyCredParams());
        foreach ($attestation->getPubKeyCredParams() as $param) {
            $this->assertSame('public-key', $param->getType());
            $this->assertContains(
                $param->getAlg(),
                $this->app[PublicKeyCredentialParametersCollection::class]->map->getAlg()->all()
            );
        }

        $this->assertSame(60000, $attestation->getTimeout());
        $this->assertCount(0, $attestation->getExcludeCredentials());

        $this->assertEmpty($attestation->getExtensions());
        $this->assertEquals(16, strlen($attestation->getChallenge()));

        $this->assertSame('preferred', $attestation->getAuthenticatorSelection()->getUserVerification());
        $this->assertNull($attestation->getAuthenticatorSelection()->getAuthenticatorAttachment());
        $this->assertNull($attestation->getAuthenticatorSelection()->getResidentKey());
        $this->assertFalse($attestation->getAuthenticatorSelection()->isRequireResidentKey());
    }

    public function test_attest_always_returns_new_challenge()
    {
        Route::get('something', function () {
            return response()->noContent();
        });

        $this->get('something')->assertNoContent();

        $request = $this->mock(Request::class);

        $request->shouldReceive('getHttpHost')
            ->andReturn('test_host');

        $request->shouldReceive('ip')
            ->andReturn('127.0.0.1');

        $first = $this->app[WebAuthnAttestCreator::class]->generateAttestation($this->user);
        $second = $this->app[WebAuthnAttestCreator::class]->generateAttestation($this->user);

        $this->assertNotSame($first->getChallenge(), $second->getChallenge());
    }

    public function test_attest_with_preferred_resident_key()
    {
        $this->app['config']->set('larapass.userless', 'preferred');

        Route::get('something', function () {
            return response()->noContent();
        });

        $this->get('something')->assertNoContent();

        $request = $this->mock(Request::class);

        $request->shouldReceive('getHttpHost')
            ->andReturn('test_host');

        $request->shouldReceive('ip')
            ->andReturn('127.0.0.1');

        $attestation = $this->app[WebAuthnAttestCreator::class]->generateAttestation($this->user);

        $this->assertSame('preferred', $attestation->getAuthenticatorSelection()->getResidentKey());
    }

    public function test_attest_returns_null_if_no_assertion_was_created()
    {
        $attestation = $this->app[WebAuthnAttestCreator::class]->retrieveAttestation($this->user);

        $this->assertNull($attestation);
    }

    public function test_attest_returns_excluded_credentials()
    {
        $this->app['config']->set('larapass.unique', true);

        Route::get('something', function () {
            return response()->noContent();
        });

        $this->get('something')->assertNoContent();

        $request = $this->mock(Request::class);

        $request->shouldReceive('getHttpHost')
            ->andReturn('test_host');

        $request->shouldReceive('ip')
            ->andReturn('127.0.0.1');

        $cache = $this->mock(Repository::class);

        $cache->shouldReceive('forget');

        $cache->shouldReceive('get')->andReturn(
            $creation = new PublicKeyCredentialCreationOptions(
                $this->app[PublicKeyCredentialRpEntity::class],
                $this->user->userEntity(),
                random_bytes(16),
                [],
                60000,
                $this->user->allCredentialDescriptors(),
                $this->app[AuthenticatorSelectionCriteria::class],
                'none',
                $this->app[AuthenticationExtensionsClientInputs::class]
            )
        );

        $this->mock(CacheFactoryContract::class)
            ->shouldReceive('store')
            ->with(null)
            ->andReturn($cache);

        $attestation = $this->app[WebAuthnAttestCreator::class]->retrieveAttestation($this->user);

        $this->assertCount(1, $attestation->getExcludeCredentials());
        $this->assertSame(
            'test_credential_foo', Base64Url::encode(Arr::first($attestation->getExcludeCredentials())->getId())
        );
    }

    public function test_attest_validates_attestation()
    {
        Route::get('something', function () {
            return response()->noContent();
        });

        $this->get('something')->assertNoContent();

        $cache = $this->mock(Repository::class);

        $cache->shouldReceive('forget');

        $cache->shouldReceive('get')->andReturn(
            $creation = new PublicKeyCredentialCreationOptions(
                $this->app[PublicKeyCredentialRpEntity::class],
                $this->user->userEntity(),
                random_bytes(16),
                [],
                60000,
                [],
                $this->app[AuthenticatorSelectionCriteria::class],
                'none',
                $this->app[AuthenticationExtensionsClientInputs::class]
            )
        );

        $this->mock(CacheFactoryContract::class)
            ->shouldReceive('store')
            ->with(null)
            ->andReturn($cache);

        $credential = new PublicKeyCredential(
            'test_credential_id',
            'public-key',
            'a04f39f8ba6a4a19b98a0579bf76505ea6d55730745274616166ef827b649506',
            $response = Mockery::mock(AuthenticatorAttestationResponse::class)
        );

        $this->mock(PublicKeyCredentialLoader::class)
            ->shouldReceive('loadArray')
            ->with(['foo' => 'bar'])
            ->andReturn($credential);

        $this->mock(AuthenticatorAttestationResponseValidator::class)
            ->shouldReceive('check')
            ->with(
                $response,
                Mockery::type(PublicKeyCredentialCreationOptions::class),
                Mockery::type(ServerRequestInterface::class),
                [0 => 'localhost']
            )->andReturn(
                $source = new PublicKeyCredentialSource(
                    'test_id',
                    'test_type',
                    [],
                    'test_attestation',
                    new EmptyTrustPath(),
                    Uuid::uuid4(),
                    'test_public_key',
                    'test_user_handle',
                    0
                )
            );

        $credential = $this->app[WebAuthnAttestValidator::class]->validate(['foo' => 'bar'], $this->user);

        $this->assertSame($source, $credential);
    }

    public function test_attestation_fails_on_invalid_argument_exception()
    {
        Route::get('something', function () {
            return response()->noContent();
        });

        $cache = $this->mock(Repository::class);

        $cache->shouldReceive('forget');

        $cache->shouldReceive('get')->andReturn(
            $creation = new PublicKeyCredentialCreationOptions(
                $this->app[PublicKeyCredentialRpEntity::class],
                $this->user->userEntity(),
                random_bytes(16),
                [],
                60000,
                [],
                $this->app[AuthenticatorSelectionCriteria::class],
                'none',
                $this->app[AuthenticationExtensionsClientInputs::class]
            )
        );

        $this->mock(CacheFactoryContract::class)
            ->shouldReceive('store')
            ->with(null)
            ->andReturn($cache);

        $credential = new PublicKeyCredential(
            'test_credential_id',
            'public-key',
            'a04f39f8ba6a4a19b98a0579bf76505ea6d55730745274616166ef827b649506',
            $response = Mockery::mock(AuthenticatorAttestationResponse::class)
        );

        $this->mock(PublicKeyCredentialLoader::class)
            ->shouldReceive('loadArray')
            ->with(['foo' => 'bar'])
            ->andReturn($credential);

        $this->mock(AuthenticatorAttestationResponseValidator::class)
            ->shouldReceive('check')
            ->with(
                $response,
                Mockery::type(PublicKeyCredentialCreationOptions::class),
                Mockery::type(ServerRequestInterface::class),
                [0 => 'localhost']
            )->andThrow(new InvalidArgumentException);

        $result = $this->app[WebAuthnAttestValidator::class]->validate(['foo' => 'bar'], $this->user);

        $this->assertFalse($result);
    }

    public function test_attestation_throws_non_invalid_argument_exception()
    {
        $this->expectException(Exception::class);

        Route::get('something', function () {
            return response()->noContent();
        });

        $cache = $this->mock(Repository::class);

        $cache->shouldReceive('get')->andReturn(
            $creation = new PublicKeyCredentialCreationOptions(
                $this->app[PublicKeyCredentialRpEntity::class],
                $this->user->userEntity(),
                random_bytes(16),
                [],
                60000,
                [],
                $this->app[AuthenticatorSelectionCriteria::class],
                'none',
                $this->app[AuthenticationExtensionsClientInputs::class]
            )
        );

        $this->mock(CacheFactoryContract::class)
            ->shouldReceive('store')
            ->with(null)
            ->andReturn($cache);

        $credential = new PublicKeyCredential(
            'test_credential_id',
            'public-key',
            'a04f39f8ba6a4a19b98a0579bf76505ea6d55730745274616166ef827b649506',
            $response = Mockery::mock(AuthenticatorAttestationResponse::class)
        );

        $this->mock(PublicKeyCredentialLoader::class)
            ->shouldReceive('loadArray')
            ->with(['foo' => 'bar'])
            ->andReturn($credential);

        $this->mock(AuthenticatorAttestationResponseValidator::class)
            ->shouldReceive('check')
            ->with(
                $response,
                Mockery::type(PublicKeyCredentialCreationOptions::class),
                Mockery::type(ServerRequestInterface::class)
            )->andThrow(new Exception());

        $this->app[WebAuthnAttestValidator::class]->validate(['foo' => 'bar'], $this->user);
    }

    public function test_attestation_fails_if_attestation_doesnt_exists()
    {
        Route::get('something', function () {
            return response()->noContent();
        });

        $this->get('something')->assertNoContent();

        $cache = $this->mock(Repository::class);

        $cache->shouldReceive('forget');

        $cache->shouldReceive('get')->andReturnNull();

        $this->mock(CacheFactoryContract::class)
            ->shouldReceive('store')
            ->with(null)
            ->andReturn($cache);

        $this->mock(PublicKeyCredentialLoader::class)
            ->shouldNotReceive('loadArray');

        $this->mock(AuthenticatorAttestationResponseValidator::class)
            ->shouldNotReceive('check');

        $credential = $this->app[WebAuthnAttestValidator::class]->validate(['foo' => 'bar'], $this->user);

        $this->assertFalse($credential);
    }

    public function test_attestation_fails_if_response_invalid()
    {
        Route::get('something', function () {
            return response()->noContent();
        });

        $this->get('something')->assertNoContent();

        $cache = $this->mock(Repository::class);

        $cache->shouldReceive('forget');
        $cache->shouldReceive('get')->andReturn(
            $creation = new PublicKeyCredentialCreationOptions(
                $this->app[PublicKeyCredentialRpEntity::class],
                $this->user->userEntity(),
                random_bytes(16),
                [],
                60000,
                [],
                $this->app[AuthenticatorSelectionCriteria::class],
                'none',
                $this->app[AuthenticationExtensionsClientInputs::class]
            )
        );

        $this->mock(CacheFactoryContract::class)
            ->shouldReceive('store')
            ->with(null)
            ->andReturn($cache);

        $credential = new PublicKeyCredential(
            'test_credential_id',
            'public-key',
            'a04f39f8ba6a4a19b98a0579bf76505ea6d55730745274616166ef827b649506',
            new class extends AuthenticatorResponse {
                public function __construct()
                {

                }
            }
        );

        $this->mock(PublicKeyCredentialLoader::class)
            ->shouldReceive('loadArray')
            ->with(['foo' => 'bar'])
            ->andReturn($credential);

        $this->mock(AuthenticatorAttestationResponseValidator::class)
            ->shouldNotReceive('check');

        $credential = $this->app[WebAuthnAttestValidator::class]->validate(['foo' => 'bar'], $this->user);

        $this->assertFalse($credential);
    }

    public function test_reaches_attestation_validator()
    {
        Route::get('something', function () {
            return response()->noContent();
        });

        $this->get('something')->assertNoContent();

        $cache = $this->mock(Repository::class);

        $cache->shouldReceive('forget');

        $cache->shouldReceive('get')->andReturn(
            $creation = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(
                    'Laravel',
                    'webauthn.spomky-labs.com'
                ),
                $this->user->userEntity(),
                base64_decode('XKADkZSW9B4h0Fek8KbhQun3m4dfJYN3ci9wdXDNJvU='),
                [],
                60000,
                [],
                $this->app[AuthenticatorSelectionCriteria::class],
                'none',
                $this->app[AuthenticationExtensionsClientInputs::class]
            )
        );

        $this->mock(CacheFactoryContract::class)
            ->shouldReceive('store')
            ->with(null)
            ->andReturn($cache);

        $credential = [
            'id' => 'WsVEgVplFhLkRd68yW3KAIyVJ90ZsQOHFjnL71YirSY',
            'type' => 'public-key',
            'rawId' => 'WsVEgVplFhLkRd68yW3KAIyVJ90ZsQOHFjnL71YirSY=',
            'response' => [
                'clientDataJSON' => 'ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5jcmVhdGUiLA0KCSJjaGFsbGVuZ2UiIDogIlhLQURrWlNXOUI0aDBGZWs4S2JoUXVuM200ZGZKWU4zY2k5d2RYRE5KdlUiLA0KCSJvcmlnaW4iIDogImh0dHBzOi8vd2ViYXV0aG4uc3BvbWt5LWxhYnMuY29tIiwNCgkidG9rZW5CaW5kaW5nIiA6IA0KCXsNCgkJInN0YXR1cyIgOiAic3VwcG9ydGVkIg0KCX0NCn0=',
                'attestationObject' => 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBZ5YE6oKCTpikraFLRGLQ1zqOxGkTDakbGTB0WSKfdKNZRQAAAABgKLAXsdRMArSzr82vyWuyACBaxUSBWmUWEuRF3rzJbcoAjJUn3RmxA4cWOcvvViKtJqQBAwM5AQAgWQEAv5VUWjpRGBvp2zawiX2JKC9WSDvVxlLfqNqU1EYsdN6iNg16FFF/0EHkt7tJz9wkwC3Cx5vYFyblUw7UF5m8qS579OcGRjvb6MHj+MQFuOKCoowBMY/VjuF+TT14deKMuWtShT2MCab1gtfnkuGAlEcu2CASvAwtbEPKZ2JkaouWWaJ3hDOYTXWYgCgtM5DqqnN9JUZjXrgmAfQC82SYh6ZAV+MQ2s4RG2jP/dvEt235oFSIkr3JEqhStQvJ+CFmjVk67oFtofcISax44CynCd2Lr89inWU1B0JwSB1oyuLPq5HCQuSmFed/piGjVfFgCbN0tCXJkAGufkDXE3J4xSFDAQAB',
            ],
        ];

        $result = $this->app[WebAuthnAttestValidator::class]->validate($credential, $this->user);

        $this->assertInstanceOf(PublicKeyCredentialSource::class, $result);
    }
}

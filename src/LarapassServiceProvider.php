<?php

namespace DarkGhostHunter\Larapass;

use Cose\Algorithm\Manager as CoseAlgorithmManager;
use DarkGhostHunter\Larapass\Auth\CredentialBroker;
use DarkGhostHunter\Larapass\Auth\EloquentWebAuthnProvider;
use DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable;
use DarkGhostHunter\Larapass\Eloquent\WebAuthnCredential as WebAuthnAuthenticationModel;
use DarkGhostHunter\Larapass\WebAuthn\PublicKeyCredentialParametersCollection;
use DarkGhostHunter\Larapass\WebAuthn\WebAuthnAssertValidator;
use DarkGhostHunter\Larapass\WebAuthn\WebAuthnAttestCreator;
use DarkGhostHunter\Larapass\WebAuthn\WebAuthnAttestValidator;
use Illuminate\Auth\Passwords\DatabaseTokenRepository;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Str;
use Psr\Log\LoggerInterface;
use RuntimeException;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Counter\CounterChecker;
use Webauthn\Counter\ThrowExceptionIfInvalid;
use Webauthn\MetadataService\MetadataStatementRepository;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\TokenBinding\IgnoreTokenBindingHandler;
use Webauthn\TokenBinding\TokenBindingHandler;

class LarapassServiceProvider extends ServiceProvider
{
    /**
     * Path to the migration file.
     *
     * @var string
     */
    protected const MIGRATION_FILE = __DIR__ . '/../database/migrations/2020_04_02_000000_create_web_authn_tables.php';

    /**
     * Register the application services.
     *
     * @return void
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/larapass.php', 'larapass');

        $this->app->alias(Authenticatable::class, WebAuthnAuthenticatable::class);

        $this->bindWebAuthnBasePackage();

        $this->app->bind(WebAuthnAttestCreator::class);
        $this->app->bind(WebAuthnAttestValidator::class);
        $this->app->bind(WebAuthnAssertValidator::class);
    }

    /**
     * Bind all the WebAuthn package services to the Service Container.
     *
     * @return void
     */
    protected function bindWebAuthnBasePackage(): void
    {
        // And from here the shit hits the fan. But it's needed to make the package modular,
        // testable and catchable by the developer when he needs to override anything.
        $this->app->singleton(
            AttestationStatementSupportManager::class,
            static function () {
                return tap(new AttestationStatementSupportManager())->add(new NoneAttestationStatementSupport());
            }
        );

        $this->app->singleton(
            MetadataStatementRepository::class,
            static function () {
                return null;
            }
        );

        $this->app->singleton(
            AttestationObjectLoader::class,
            static function ($app) {
                return new AttestationObjectLoader(
                    $app[AttestationStatementSupportManager::class],
                    $app[MetadataStatementRepository::class],
                    $app[LoggerInterface::class]
                );
            }
        );

        $this->app->singleton(
            PublicKeyCredentialLoader::class,
            static function ($app) {
                return new PublicKeyCredentialLoader(
                    $app[AttestationObjectLoader::class],
                    $app['log']
                );
            }
        );

        $this->app->bind(
            PublicKeyCredentialSourceRepository::class,
            static function () {
                return new WebAuthnAuthenticationModel();
            }
        );

        $this->app->bind(
            TokenBindingHandler::class,
            static function () {
                return new IgnoreTokenBindingHandler();
            }
        );

        $this->app->bind(
            ExtensionOutputCheckerHandler::class,
            static function () {
                return new ExtensionOutputCheckerHandler();
            }
        );

        $this->app->bind(
            CoseAlgorithmManager::class,
            static function ($app) {
                $manager = new CoseAlgorithmManager();

                foreach ($app['config']->get('larapass.algorithms') as $algorithm) {
                    $manager->add(new $algorithm());
                }

                return $manager;
            }
        );

        $this->app->bind(
            AuthenticatorAttestationResponseValidator::class,
            static function ($app) {
                return new AuthenticatorAttestationResponseValidator(
                    $app[AttestationStatementSupportManager::class],
                    $app[PublicKeyCredentialSourceRepository::class],
                    $app[TokenBindingHandler::class],
                    $app[ExtensionOutputCheckerHandler::class],
                    $app[MetadataStatementRepository::class],
                    $app['log']
                );
            }
        );

        $this->app->bind(
            CounterChecker::class,
            static function ($app) {
                return new ThrowExceptionIfInvalid($app['log']);
            }
        );

        $this->app->bind(
            AuthenticatorAssertionResponseValidator::class,
            static function ($app) {
                return new AuthenticatorAssertionResponseValidator(
                    $app[PublicKeyCredentialSourceRepository::class],
                    $app[TokenBindingHandler::class],
                    $app[ExtensionOutputCheckerHandler::class],
                    $app[CoseAlgorithmManager::class],
                    $app[CounterChecker::class],
                    $app['log']
                );
            }
        );

        $this->app->bind(
            PublicKeyCredentialRpEntity::class,
            static function ($app) {
                $config = $app['config'];

                return new PublicKeyCredentialRpEntity(
                    $config->get('larapass.relaying_party.name'),
                    $config->get('larapass.relaying_party.id'),
                    $config->get('larapass.relaying_party.icon')
                );
            }
        );

        $this->app->bind(
            AuthenticatorSelectionCriteria::class,
            static function ($app) {
                $config = $app['config'];

                $selection = new WebAuthn\AuthenticatorSelectionCriteria(
                    $config->get('larapass.cross-plataform')
                );

                if ($userless = $config->get('larapass.userless')) {
                    $selection->setResidentKey($userless);
                }

                return $selection;
            }
        );

        $this->app->bind(
            PublicKeyCredentialParametersCollection::class,
            static function ($app) {
                return PublicKeyCredentialParametersCollection::make($app[CoseAlgorithmManager::class]->list())
                    ->map(
                        static function ($algorithm) {
                            return new PublicKeyCredentialParameters('public-key', $algorithm);
                        }
                    );
            }
        );

        $this->app->bind(
            AuthenticationExtensionsClientInputs::class,
            static function () {
                return new AuthenticationExtensionsClientInputs();
            }
        );

        $this->app->singleton(
            CredentialBroker::class,
            static function ($app) {
                if (!$config = $app['config']['auth.passwords.webauthn']) {
                    throw new RuntimeException('You must set the [webauthn] key broker in [auth] config.');
                }

                $key = $app['config']['app.key'];

                if (Str::startsWith($key, 'base64:')) {
                    $key = base64_decode(substr($key, 7));
                }

                return new CredentialBroker(
                    new DatabaseTokenRepository(
                        $app['db']->connection($config['connection'] ?? null),
                        $app['hash'],
                        $config['table'],
                        $key,
                        $config['expire'],
                        $config['throttle'] ?? 0
                    ),
                    $app['auth']->createUserProvider($config['provider'] ?? null)
                );
            }
        );
    }

    /**
     * Bootstrap the application services.
     *
     * @return void
     */
    public function boot(): void
    {
        $this->loadViewsFrom(__DIR__ . '/../resources/views', 'larapass');
        $this->loadTranslationsFrom(__DIR__ . '/../resources/lang', 'larapass');

        $this->app['auth']->provider(
            'eloquent-webauthn',
            static function ($app, $config) {
                return new EloquentWebAuthnProvider(
                    $app['config'],
                    $app[WebAuthnAssertValidator::class],
                    $app[Hasher::class],
                    $config['model']
                );
            }
        );

        $this->app['router']->aliasMiddleware('webauthn.confirm', Http\Middleware\RequireWebAuthn::class);

        if ($this->app->runningInConsole()) {
            $this->publishFiles();
        }
    }

    /**
     * Publish config, view and migrations files.
     *
     * @return void
     */
    protected function publishFiles() : void
    {
        $this->publishes([__DIR__ . '/../config/larapass.php' => config_path('larapass.php')], 'config');
        $this->publishes([__DIR__ . '/../stubs' => app_path('Http/Controllers/Auth')], 'controllers');
        $this->publishes([__DIR__ . '/../resources/js' => public_path('vendor/larapass/js')], 'public');
        $this->publishes([__DIR__ . '/../resources/views' => resource_path('views/vendor/larapass')], 'views');

        $this->publishes([static::MIGRATION_FILE => static::generateDatabasePublishPath()], 'migrations');
    }

    /**
     * Creates a final database path for the migration.
     *
     * @return string
     */
    protected static function generateDatabasePublishPath(): string
    {
        return database_path('migrations/' . now()->format('Y_m_d_His') . '_create_web_authn_tables.php');
    }
}

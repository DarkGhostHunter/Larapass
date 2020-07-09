<?php

namespace Tests;

use Ramsey\Uuid\Uuid;
use Illuminate\Support\Str;
use Orchestra\Testbench\TestCase;
use Tests\Stubs\TestWebAuthnUser;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Date;
use Webauthn\TrustPath\EmptyTrustPath;
use Webauthn\PublicKeyCredentialSource;
use Illuminate\Database\Eloquent\Model;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\PublicKeyCredentialDescriptor;
use Illuminate\Database\Eloquent\Relations\HasMany;
use DarkGhostHunter\Larapass\WebAuthnAuthentication;

class WebAuthnAuthenticationTest extends TestCase
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
                    realpath(__DIR__ . '/../database/migrations'),
                ],
            ]);

            $uuid = Str::uuid();

            $this->user = TestWebAuthnUser::make()->forceFill([
                'name'     => 'john',
                'email'    => 'john.doe@mail.com',
                'password' => '$2y$10$FLIykVJWDsYSVMJyaFZZfe4tF5uBTnGsosJBL.ZfAAHsYgc27FSdi',
            ]);

            $this->user->save();

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
                'user_handle'      => $uuid->toString(),
                'created_at'       => now()->toDateTimeString(),
                'updated_at'       => now()->toDateTimeString(),
            ]);

            DB::table('web_authn_credentials')->insert([
                'id'               => 'test_credential_bar',
                'user_id'          => 1,
                'type'             => 'public_key',
                'transports'       => json_encode([]),
                'attestation_type' => 'none',
                'trust_path'       => json_encode(['type' => EmptyTrustPath::class]),
                'aaguid'           => Str::uuid(),
                'public_key'       => 'public_key_bar',
                'counter'          => 0,
                'user_handle'      => $uuid->toString(),
                'created_at'       => now()->toDateTimeString(),
                'updated_at'       => now()->toDateTimeString(),
                'disabled_at'      => null,
            ]);
        });

        parent::setUp();
    }

    public function test_returns_relation_instance_on_method_call()
    {
        $model = new class extends Model {
            use WebAuthnAuthentication;
        };

        $this->assertInstanceOf(HasMany::class, $model->webAuthnCredentials());
    }

    public function test_cycles_entity_when_no_credential_exists()
    {
        $user = TestWebAuthnUser::make()->forceFill([
            'name'     => 'mike',
            'email'    => 'mike.doe@mail.com',
            'password' => '$2y$10$FLIykVJWDsYSVMJyaFZZfe4tF5uBTnGsosJBL.ZfAAHsYgc27FSdi',
        ]);

        $user->save();

        $entity = $user->userEntity();

        $this->assertInstanceOf(PublicKeyCredentialUserEntity::class, $entity);

        $this->assertNotSame($entity->getId(), $user->userEntity()->getId());
    }

    public function test_returns_user_entity_with_handle_used_previously()
    {
        $this->assertSame($this->user->userEntity()->getId(), $this->user->userEntity()->getId());
    }

    public function test_returns_user_entity_with_handle_used_in_disabled_credential()
    {
        $entity = $this->user->userEntity()->getId();

        DB::table('web_authn_credentials')
            ->where('test_credential_bar')
            ->update(['disabled_at' => now()]);

        $this->assertSame($entity, $this->user->userEntity()->getId());
    }

    public function test_returns_all_credentials_as_excluded()
    {
        $this->assertCount(2, $this->user->attestationExcludedCredentials());

        DB::table('web_authn_credentials')->insert([
            'id'               => 'test_credential_baz',
            'user_id'          => 1,
            'type'             => 'public_key',
            'transports'       => json_encode([]),
            'attestation_type' => 'none',
            'trust_path'       => json_encode(['type' => EmptyTrustPath::class]),
            'aaguid'           => Str::uuid(),
            'public_key'       => 'public_key_bar',
            'counter'          => 0,
            'user_handle'      => $this->user->userEntity()->getId(),
            'created_at'       => now()->toDateTimeString(),
            'updated_at'       => now()->toDateTimeString(),
            'disabled_at'      => now()->toDateTimeString(),
        ]);

        $this->assertCount(3, $this->user->webAuthnCredentials()->withTrashed()->get());
        $this->assertCount(2, $this->user->attestationExcludedCredentials());
    }

    public function test_checks_if_credentials_id_exists()
    {
        $this->assertFalse($this->user->hasCredential('doesnt_exists'));
        $this->assertTrue($this->user->hasCredential('test_credential_foo'));
    }

    public function test_adds_a_new_credential()
    {
        Date::setTestNow($now = Date::create(2020, 01, 04, 16, 30));

        $this->user->addCredential(new PublicKeyCredentialSource(
            'test_credential_id',
            'public_key',
            [],
            'none',
            new EmptyTrustPath(),
            $uuid = Uuid::uuid4(),
            $key = 'testKey',
            $handle = Uuid::uuid4(),
            0
        ));

        $this->assertDatabaseHas('web_authn_credentials', [
            'id'               => 'test_credential_id',
            'user_id'          => 1,
            'type'             => 'public_key',
            'transports'       => json_encode([]),
            'attestation_type' => 'none',
            'trust_path'       => json_encode(['type' => EmptyTrustPath::class]),
            'aaguid'           => $uuid,
            'counter'          => 0,
            'user_handle'      => $handle,
            'created_at'       => $now->toDateTimeString(),
            'updated_at'       => $now->toDateTimeString(),
            'disabled_at'      => null,
            'public_key'       => 'testKey',
        ]);
    }

    public function test_enables_and_disables_credentials()
    {
        Date::setTestNow($now = Date::create(2020, 04, 01, 16, 30));

        $this->user->disableCredential('test_credential_foo');
        $this->assertDatabaseHas('web_authn_credentials', [
            'id'          => 'test_credential_foo',
            'disabled_at' => $now->toDateTimeString(),
        ]);

        $this->user->disableCredential(['test_credential_foo', 'test_credential_bar']);
        $this->assertCount(2, DB::table('web_authn_credentials')->whereNotNull('disabled_at')->get());

        $this->user->enableCredential('test_credential_foo');
        $this->assertDatabaseHas('web_authn_credentials', [
            'id'          => 'test_credential_foo',
            'disabled_at' => null,
        ]);

        $this->user->enableCredential(['test_credential_foo', 'test_credential_bar']);
        $this->assertCount(2, DB::table('web_authn_credentials')->whereNull('disabled_at')->get());
    }

    public function test_disables_all_credentials()
    {
        $this->user->disableAllCredentials();
        $this->assertDatabaseHas('web_authn_credentials', [
            'id'          => 'test_credential_foo',
        ]);
        $this->assertDatabaseHas('web_authn_credentials', [
            'id'          => 'test_credential_bar',
        ]);
        $this->assertDatabaseMissing('web_authn_credentials', [
            'disabled_at' => null,
        ]);
    }

    public function test_disables_all_credentials_except_some()
    {
        Date::setTestNow($now = Date::create(2020, 04, 01, 16, 30));

        $this->user->disableAllCredentials('test_credential_bar');
        $this->assertDatabaseHas('web_authn_credentials', [
            'id'          => 'test_credential_foo',
            'disabled_at' => $now->toDateTimeString(),
        ]);
        $this->assertDatabaseHas('web_authn_credentials', [
            'id'          => 'test_credential_bar',
            'disabled_at' => null,
        ]);
    }

    public function test_deletes_credentials()
    {
        $this->user->removeCredential('test_credential_foo');
        $this->assertDatabaseMissing('web_authn_credentials', [
            'id' => 'test_credential_foo',
        ]);

        DB::table('web_authn_credentials')->insert([
            'id'               => 'test_credential_baz',
            'user_id'          => 1,
            'type'             => 'public_key',
            'transports'       => json_encode([]),
            'attestation_type' => 'none',
            'trust_path'       => json_encode(['type' => EmptyTrustPath::class]),
            'aaguid'           => Str::uuid(),
            'public_key'       => 'public_key_bar',
            'counter'          => 0,
            'user_handle'      => $this->user->userEntity()->getId(),
            'created_at'       => now()->toDateTimeString(),
            'updated_at'       => now()->toDateTimeString(),
            'disabled_at'      => now()->toDateTimeString(),
        ]);

        $this->user->removeCredential(['test_credential_bar', 'test_credential_baz']);
        $this->assertDatabaseMissing('web_authn_credentials', [
            'id' => 'test_credential_bar',
        ]);
        $this->assertDatabaseMissing('web_authn_credentials', [
            'id' => 'test_credential_baz',
        ]);
    }

    public function test_deletes_all_credentials()
    {
        $this->user->flushCredentials();

        $this->assertDatabaseCount('web_authn_credentials', 0);
    }

    public function test_deletes_all_credentials_except_one()
    {
        $this->user->flushCredentials('test_credential_foo');

        $this->assertDatabaseCount('web_authn_credentials', 1);
        $this->assertDatabaseHas('web_authn_credentials', [
            'id' => 'test_credential_foo',
        ]);
    }

    public function test_checks_if_credential_is_enabled()
    {
        $this->assertTrue($this->user->hasCredentialEnabled('test_credential_foo'));

        DB::table('web_authn_credentials')->where('id', 'test_credential_foo')
            ->update(['disabled_at' => now()]);

        $this->assertFalse($this->user->hasCredentialEnabled('test_credential_foo'));
        $this->assertFalse($this->user->hasCredentialEnabled('doesnt_exists'));
    }

    public function test_retrieves_all_credentials_as_descriptors_except_disabled()
    {
        $descriptors = $this->user->allCredentialDescriptors();

        $this->assertCount(2, $descriptors);

        foreach ($descriptors as $descriptor) {
            $this->assertInstanceOf(PublicKeyCredentialDescriptor::class, $descriptor);
        }

        $this->user->disableCredential('test_credential_foo');

        $descriptors = $this->user->allCredentialDescriptors();

        $this->assertCount(1, $descriptors);
    }

    public function test_returns_user_from_given_credential_id()
    {
        $user = call_user_func([$this->user, 'getFromCredentialId'], 'test_credential_foo');

        $this->assertTrue($this->user->is($user));

        $this->assertNull(call_user_func([$this->user, 'getFromCredentialId'], 'test_credential_baz'));

        DB::table('web_authn_credentials')->where('id', 'test_credential_foo')
            ->update(['disabled_at' => now()]);

        $this->assertNull(call_user_func([$this->user, 'getFromCredentialId'], 'test_credential_foo'));
    }

    public function test_returns_user_from_given_user_handle()
    {
        $user = call_user_func([$this->user, 'getFromCredentialUserHandle'], $this->user->userHandle());

        $this->assertTrue($this->user->is($user));

        $this->assertNull(call_user_func([$this->user, 'getFromCredentialUserHandle'], 'nope'));

        DB::table('web_authn_credentials')->update(['disabled_at' => now()]);

        $this->assertNull(
            call_user_func([$this->user, 'getFromCredentialUserHandle'], $this->user->userHandle())
        );
    }
}

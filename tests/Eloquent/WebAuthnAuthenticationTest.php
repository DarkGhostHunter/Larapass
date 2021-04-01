<?php

namespace Tests\Eloquent;

use Base64Url\Base64Url;
use DarkGhostHunter\Larapass\Eloquent\WebAuthnCredential;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Orchestra\Testbench\TestCase;
use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidInterface;
use Tests\RegistersPackage;
use Tests\RunsPublishableMigrations;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

class WebAuthnAuthenticationTest extends TestCase
{
    use RegistersPackage,
        RunsPublishableMigrations;

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
        });

        parent::setUp();
    }

    public function test_hides_from_serialization()
    {
        DB::table('web_authn_credentials')->insert([
            'id'               => 'test_credential_id',
            'name'             => 'foo',
            'user_id'          => 1,
            'type'             => 'public_key',
            'transports'       => json_encode([]),
            'attestation_type' => 'none',
            'trust_path'       => json_encode(['type' => EmptyTrustPath::class]),
            'aaguid'           => Str::uuid(),
            'public_key'       => 'public_key_bar',
            'counter'          => 0,
            'user_handle'      => Str::uuid()->toString(),
            'created_at'       => now()->toDateTimeString(),
            'updated_at'       => now()->toDateTimeString(),
            'disabled_at'      => null,
        ]);

        $this->assertSame([
            'id'         => Base64Url::decode('test_credential_id'),
            'name'       => 'foo',
            'type'       => 'public_key',
            'transports' => [],
        ], WebAuthnCredential::first()->toArray());
    }

    public function test_can_fill_name()
    {
        $model = WebAuthnCredential::make([
            'name' => 'foo',
        ]);

        $this->assertSame('foo', $model->name);
    }

    public function test_sets_aaguid_as_uuid()
    {
        $uuid = '6028b017-b1d4-4c02-b4b3-afcdafc96bb2';

        $model = WebAuthnCredential::make();

        $model->aaguid = $uuid;
        $this->assertInstanceOf(UuidInterface::class, $model->aaguid);
        $this->assertSame($model->aaguid->toString(), $uuid);

        $model->aaguid = 'YCiwF7HUTAK0s6/Nr8lrsg==';
        $this->assertInstanceOf(UuidInterface::class, $model->aaguid);
        $this->assertSame($model->aaguid->toString(), $uuid);
    }

    public function test_saves_credential_public_key_as_binary_string()
    {
        $key = 'pAEDAzkBACBZAQDwn2Ee7V+9GNDn2iCU2plQnIVmZG/vOiXSHb9TQzC5806bGzLV918+1SLFhMhlX5jua2rdXt65nYw9Eln7mbmVxLBDmEm2wod6wP2HinC9HPsYwr75tMRakLMNFfH4Xx4lEsjulRmv68yl/N8XH64X8LKe2GBxjqcuJR+c3LbW4D5dWt/1pGL8fS1UbO3abA/d3IeEsP8RpEz5eVo6qBhb4r0VTo2NMeq75saBHIj4whqo6qsRqRvBmK2d9NAecBFFRIQ31NUtEQZPqXOzkbXGehDi7c3YJPBkTW9kMqcosob9Vlru+vVab+1PnFRdqaklR1UtmhrWte/wB61Hm3xdIUMBAAE=';

        $model = WebAuthnCredential::make();

        $model->public_key = $key;

        $this->assertSame($key, $model->getAttributes()['public_key']);
    }

    public function test_finds_one_by_credential_id()
    {
        $model = WebAuthnCredential::make();

        $this->assertNull(
            $model->findOneByCredentialId(Base64Url::decode('dGVzdF9jcmVkZW50aWFsX2lk'))
        );

        DB::table('web_authn_credentials')->insert([
            'id'               => 'dGVzdF9jcmVkZW50aWFsX2lk',
            'user_id'          => 1,
            'type'             => 'public_key',
            'transports'       => json_encode([]),
            'attestation_type' => 'none',
            'trust_path'       => json_encode(['type' => EmptyTrustPath::class]),
            'aaguid'           => Str::uuid(),
            'public_key'       => 'public_key_bar',
            'counter'          => 0,
            'user_handle'      => Str::uuid()->toString(),
            'created_at'       => now()->toDateTimeString(),
            'updated_at'       => now()->toDateTimeString(),
            'disabled_at'      => null,
        ]);

        $this->assertInstanceOf(
            PublicKeyCredentialSource::class,
            $source = $model->findOneByCredentialId(Base64Url::decode('dGVzdF9jcmVkZW50aWFsX2lk'))
        );

        $this->assertSame(
            'test_credential_id',
            $source->getPublicKeyCredentialId()
        );
    }

    public function test_find_all_for_user_entity()
    {
        $model = WebAuthnCredential::make();

        $entity = new PublicKeyCredentialUserEntity(
            'test_name',
            'test_id',
            'test_display_name'
        );

        $this->assertEmpty($model->findAllForUserEntity($entity));

        DB::table('web_authn_credentials')->insert([
            'id'               => 'test_credential_id',
            'user_id'          => 1,
            'type'             => 'public_key',
            'transports'       => json_encode([]),
            'attestation_type' => 'none',
            'trust_path'       => json_encode(['type' => EmptyTrustPath::class]),
            'aaguid'           => Str::uuid(),
            'public_key'       => 'public_key_bar',
            'counter'          => 0,
            'user_handle'      => 'test_id',
            'created_at'       => now()->toDateTimeString(),
            'updated_at'       => now()->toDateTimeString(),
            'disabled_at'      => null,
        ]);

        $this->assertCount(1, $model->findAllForUserEntity($entity));
        $this->assertSame(
            Base64Url::decode('test_credential_id'),
            $model->findAllForUserEntity($entity)[0]->getPublicKeyCredentialId()
        );
    }

    public function test_only_updates_counter_from_credential_source()
    {
        DB::table('web_authn_credentials')->insert([
            'id'               => 'dGVzdF9jcmVkZW50aWFsX2lk',
            'user_id'          => 1,
            'type'             => 'public_key',
            'transports'       => json_encode([]),
            'attestation_type' => 'none',
            'trust_path'       => json_encode(['type' => EmptyTrustPath::class]),
            'aaguid'           => Str::uuid(),
            'public_key'       => 'public_key_bar',
            'counter'          => 0,
            'user_handle'      => Str::uuid()->toString(),
            'created_at'       => now()->toDateTimeString(),
            'updated_at'       => now()->toDateTimeString(),
            'disabled_at'      => null,
        ]);

        $model = WebAuthnCredential::make();

        $model->saveCredentialSource(new PublicKeyCredentialSource(
            Base64Url::decode('dGVzdF9jcmVkZW50aWFsX2lk'),
            'anything',
            ['foo', 'bar'],
            'any',
            new EmptyTrustPath(),
            Uuid::uuid4(),
            'rofl',
            'any_handle',
            10
        ));

        $model->saveCredentialSource(new PublicKeyCredentialSource(
            'invalid_id',
            'anything',
            ['foo', 'bar'],
            'any',
            new EmptyTrustPath(),
            Uuid::uuid4(),
            'rofl',
            'any_handle',
            14
        ));

        $this->assertDatabaseHas('web_authn_credentials', [
            'id'      => 'dGVzdF9jcmVkZW50aWFsX2lk',
            'counter' => 10,
        ]);
    }

    public function test_checks_if_credential_is_enabled_or_disabled()
    {
        DB::table('web_authn_credentials')->insert([
            'id'               => 'dGVzdF9jcmVkZW50aWFsX2lk',
            'user_id'          => 1,
            'type'             => 'public_key',
            'transports'       => json_encode([]),
            'attestation_type' => 'none',
            'trust_path'       => json_encode(['type' => EmptyTrustPath::class]),
            'aaguid'           => Str::uuid(),
            'public_key'       => 'public_key_bar',
            'counter'          => 0,
            'user_handle'      => Str::uuid()->toString(),
            'created_at'       => now()->toDateTimeString(),
            'updated_at'       => now()->toDateTimeString(),
            'disabled_at'      => now()->toDateTimeString(),
        ]);

        $credential = WebAuthnCredential::find('dGVzdF9jcmVkZW50aWFsX2lk');

        $this->assertNull($credential);

        $credential = WebAuthnCredential::withTrashed()->find('dGVzdF9jcmVkZW50aWFsX2lk');

        $this->assertTrue($credential->isDisabled());
        $this->assertFalse($credential->isEnabled());

        $credential->restore();

        $this->assertTrue($credential->isEnabled());
        $this->assertFalse($credential->isDisabled());
    }
}

<?php

namespace Tests\Eloquent;

use Tests\RegistersPackage;
use Illuminate\Support\Str;
use Orchestra\Testbench\TestCase;
use Illuminate\Support\Facades\DB;
use Tests\RunsPublishableMigrations;
use Ramsey\Uuid\Rfc4122\UuidInterface;
use Webauthn\TrustPath\EmptyTrustPath;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;
use DarkGhostHunter\Larapass\Eloquent\WebAuthnCredential;

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

        $this->assertSame($key, base64_encode($model->getAttributes()['public_key']));
    }

    public function test_finds_one_by_credential_id()
    {
        $model = WebAuthnCredential::make();

        $this->assertNull(
            $model->findOneByCredentialId('test_credential_id')
        );

        DB::table('web_authn_credentials')->insert([
            'id'         => 'test_credential_id',
            'user_id'               => 1,
            'is_enabled'            => true,
            'type'                  => 'public_key',
            'transports'            => json_encode([]),
            'attestation_type'      => 'none',
            'trust_path'            => json_encode(['type' => EmptyTrustPath::class]),
            'aaguid'                => Str::uuid(),
            'public_key' => 'public_key_bar',
            'counter'               => 0,
            'user_handle'           => Str::uuid()->toString(),
            'created_at'            => now()->toDateTimeString(),
            'updated_at'            => now()->toDateTimeString(),
        ]);

        $this->assertInstanceOf(PublicKeyCredentialSource::class,
            $source = $model->findOneByCredentialId('test_credential_id')
        );

        $this->assertSame(
            'test_credential_id', $source->getPublicKeyCredentialId()
        );
    }

    public function test_find_all_for_user_entity()
    {
        $model = WebAuthnCredential::make();

        $entity = new PublicKeyCredentialUserEntity(
            'test_name', 'test_id', 'test_display_name'
        );

        $this->assertEmpty($model->findAllForUserEntity($entity));

        DB::table('web_authn_credentials')->insert([
            'id'         => 'test_credential_id',
            'user_id'               => 1,
            'is_enabled'            => true,
            'type'                  => 'public_key',
            'transports'            => json_encode([]),
            'attestation_type'      => 'none',
            'trust_path'            => json_encode(['type' => EmptyTrustPath::class]),
            'aaguid'                => Str::uuid(),
            'public_key' => 'public_key_bar',
            'counter'               => 0,
            'user_handle'           => 'test_id',
            'created_at'            => now()->toDateTimeString(),
            'updated_at'            => now()->toDateTimeString(),
        ]);

        $this->assertCount(1, $model->findAllForUserEntity($entity));
        $this->assertSame(
            'test_credential_id', $model->findAllForUserEntity($entity)[0]->getPublicKeyCredentialId()
        );
    }
}
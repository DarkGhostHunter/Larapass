<?php

namespace DarkGhostHunter\Larapass\Eloquent;

use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidInterface;
use Illuminate\Database\Eloquent\Model;
use Webauthn\PublicKeyCredentialSourceRepository;

/**
 * @mixin \Illuminate\Database\Eloquent\Builder
 *
 * @property-read \DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable $user
 *
 * @property-read string $credential_id
 *
 * @property bool $is_excluded
 * @property bool $is_enabled
 * @property string $type
 * @property \Illuminate\Support\Collection $transports
 * @property string $attestation_type
 * @property \Illuminate\Support\Collection $trust_path
 * @property \Ramsey\Uuid\Uuid $aaguid
 * @property string $credential_public_key
 * @property int $counter
 * @property string $user_handle
 */
class WebAuthnCredential extends Model implements PublicKeyCredentialSourceRepository
{
    use ManagesCredentialRepository;

    /**
     * The primary key for the model.
     *
     * @var string
     */
    protected $primaryKey = 'credential_id';

    /**
     * Indicates if the IDs are auto-incrementing.
     *
     * @var bool
     */
    public $incrementing = false;

    /**
     * The "type" of the primary key ID.
     *
     * @var string
     */
    protected $keyType = 'string';

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array
     */
    protected $hidden = [
        'credential_public_key',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array
     */
    protected $casts = [
        'is_excluded' => 'boolean',
        'is_enabled'  => 'boolean',
        'transports'  => 'collection',
        'trust_path'  => 'collection',
        'counter'     => 'integer',
    ];

    /**
     * The attributes that should be mutated to dates.
     *
     * @var array
     */
    protected $dates = [
        'last_login_at',
    ];

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'credential_id',
        'type',
        'transports',
        'attestation_type',
        'trust_path',
        'aaguid',
        'credential_public_key',
        'user_handle',
        'counter',
    ];

    /**
     * The AAGUID is basically an UUID, so we will make it depending on how is encoded.
     *
     * @param  string  $value
     * @return void
     */
    public function setAaguidAttribute($value)
    {
        $this->attributes['aaguid'] = mb_strlen($value, '8bit') === 36
            ? Uuid::fromString($value)
            : Uuid::fromBytes(base64_decode($value, true));
    }

    /**
     * Returns the Aaguid as UUID.
     *
     * @param $value
     * @return \Ramsey\Uuid\UuidInterface
     */
    public function getAaguidAttribute($value)
    {
        if (! $value instanceof UuidInterface) {
            Uuid::fromString($value);
        }

        return $value;
    }

    /**
     * Sets the credential public key as binary form.
     *
     * @param  string  $value
     * @return void
     */
    public function setCredentialPublicKeyAttribute($value)
    {
        $this->attributes['credential_public_key'] = base64_decode($value);
    }

    /**
     * Return the credential public key as a Base64 string.
     *
     * @param  string  $value
     * @return string
     */
    public function getCredentialPublicKeyAttribute($value)
    {
        return base64_encode($value);
    }
}
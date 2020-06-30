<?php

namespace DarkGhostHunter\Larapass\Eloquent;

use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Builder;
use Webauthn\PublicKeyCredentialSourceRepository;

/**
 * @mixin \Illuminate\Database\Eloquent\Builder
 *
 * @property-read \DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable $user
 *
 * @property-read string $id
 *
 * @property bool $is_excluded
 * @property bool $is_enabled
 * @property string $type
 * @property \Illuminate\Support\Collection $transports
 * @property string $attestation_type
 * @property \Illuminate\Support\Collection $trust_path
 * @property \Ramsey\Uuid\Uuid $aaguid
 * @property string $public_key
 * @property int $counter
 * @property string $user_handle
 *
 * @method \Illuminate\Database\Eloquent\Builder|static enabled()
 */
class WebAuthnCredential extends Model implements PublicKeyCredentialSourceRepository
{
    use ManagesCredentialRepository;

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
        'public_key',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array
     */
    protected $casts = [
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
        'id',
        'type',
        'transports',
        'attestation_type',
        'trust_path',
        'aaguid',
        'public_key',
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
    public function setPublicKeyAttribute($value)
    {
        $this->attributes['public_key'] = base64_decode($value);
    }

    /**
     * Return the credential public key as a Base64 string.
     *
     * @param  string  $value
     * @return string
     */
    public function getPublicKeyAttribute($value)
    {
        return base64_encode($value);
    }

    /**
     * Filter the credentials for those explicitly enabled.
     *
     * @param  \Illuminate\Database\Eloquent\Builder  $builder
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopeEnabled(Builder $builder)
    {
        return $builder->where('is_enabled', true);
    }
}
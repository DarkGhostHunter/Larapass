<?php

namespace DarkGhostHunter\Larapass\Eloquent;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Webauthn\PublicKeyCredentialSourceRepository;

/**
 * @mixin \Illuminate\Database\Eloquent\Builder
 *
 * @property-read \DarkGhostHunter\Larapass\Contracts\WebAuthnAuthenticatable $user
 *
 * @property-read string $id
 *
 * @property-read string $type
 * @property-read null|string $name
 * @property-read \Illuminate\Support\Collection $transports
 * @property-read string $attestation_type
 * @property-read \Webauthn\TrustPath\TrustPath $trust_path
 * @property-read \Ramsey\Uuid\UuidInterface $aaguid
 * @property-read string $public_key
 * @property-read int $counter
 * @property-read string $user_handle
 * @property-read null|\Illuminate\Support\Carbon $disabled_at
 *
 * @property-read string $prettyId
 *
 * @method \Illuminate\Database\Eloquent\Builder|static enabled()
 */
class WebAuthnCredential extends Model implements PublicKeyCredentialSourceRepository
{
    use SoftDeletes;
    use ManagesCredentialRepository;

    /**
     * The column name for soft-deletes.
     *
     * @var string
     */
    public const DELETED_AT = 'disabled_at';

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
     * The attributes that should be visible in serialization.
     *
     * @var array
     */
    protected $visible = [
        'id',
        'name',
        'type',
        'transports',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array
     */
    protected $casts = [
        'transports' => 'collection',
        'counter' => 'integer',
        'trust_path' => Casting\TrustPathCast::class,
        'aaguid' => Casting\UuidCast::class,
    ];

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'id',
        'name',
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
     * Returns if the Credential is enabled.
     *
     * @return bool
     */
    public function isEnabled(): bool
    {
        return !$this->disabled_at;
    }

    /**
     * Returns if the Credential is disabled.
     *
     * @return bool
     */
    public function isDisabled(): bool
    {
        return !$this->isEnabled();
    }

    /**
     * Filter the credentials for those explicitly enabled.
     *
     * @param  \Illuminate\Database\Eloquent\Builder  $builder
     *
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopeEnabled(Builder $builder): Builder
    {
        return $builder->withoutTrashed();
    }

    /**
     * Convert the object into something JSON serializable.
     *
     * @return array
     */
    public function jsonSerialize()
    {
        return array_merge($this->toArray(), [$this->getKeyName() => $this->getRawOriginal($this->getKeyName())]);
    }
}

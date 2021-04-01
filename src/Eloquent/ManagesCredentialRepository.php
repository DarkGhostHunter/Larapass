<?php

namespace DarkGhostHunter\Larapass\Eloquent;

use Base64Url\Base64Url;
use Webauthn\PublicKeyCredentialDescriptor as CredentialDescriptor;
use Webauthn\PublicKeyCredentialSource as CredentialSource;
use Webauthn\PublicKeyCredentialUserEntity as UserEntity;

trait ManagesCredentialRepository
{
    /**
     * Initializes the trait.
     *
     * @returns void
     */
    protected function initializeManagesCredentialRepository()
    {
        $this->mergeCasts([$this->getKeyName() => Casting\Base64UrlCast::class]);
    }

    /**
     * Finds a source of the credentials.
     *
     * @param  string  $binaryId
     *
     * @return null|\Webauthn\PublicKeyCredentialSource
     */
    public function findOneByCredentialId(string $binaryId): ?CredentialSource
    {
        return optional($this->find(Base64Url::encode($binaryId)))->toCredentialSource();
    }

    /**
     * Return an array of all credentials for a given user.
     *
     * @param  \Webauthn\PublicKeyCredentialUserEntity  $entity
     *
     * @return array|\Webauthn\PublicKeyCredentialSource[]
     */
    public function findAllForUserEntity(UserEntity $entity): array
    {
        return static::where('user_handle', $entity->getId())->get()->map->toCredentialSource()->all();
    }

    /**
     * Update the credentials source into the storage.
     *
     * @param  \Webauthn\PublicKeyCredentialSource  $source
     */
    public function saveCredentialSource(CredentialSource $source): void
    {
        // We will only update the credential counter only if it exists.
        static::where([$this->getKeyName() => Base64Url::encode($source->getPublicKeyCredentialId())])
            ->update(['counter' => $source->getCounter()]);
    }

    /**
     * Creates a new Eloquent Model from a Credential Source.
     *
     * @param  \Webauthn\PublicKeyCredentialSource  $source
     *
     * @return self
     */
    public static function fromCredentialSource(CredentialSource $source)
    {
        return ($model = new static())->fill(
            [
                $model->getKeyName() => $source->getPublicKeyCredentialId(),
                'user_handle' => $source->getUserHandle(),
                'type' => $source->getType(),
                'transports' => $source->getTransports(),
                'attestation_type' => $source->getAttestationType(),
                'trust_path' => $source->getTrustPath()->jsonSerialize(),
                'aaguid' => $source->getAaguid()->toString(),
                'public_key' => $source->getCredentialPublicKey(),
                'counter' => $source->getCounter(),
            ]
        );
    }

    /**
     * Transform the current Eloquent model to a Credential Source.
     *
     * @return \Webauthn\PublicKeyCredentialSource
     */
    public function toCredentialSource(): CredentialSource
    {
        return new CredentialSource(
            $this->getKey(),
            $this->type,
            $this->transports->all(),
            $this->attestation_type,
            $this->trust_path,
            $this->aaguid,
            $this->public_key,
            $this->user_handle,
            $this->counter
        );
    }

    /**
     * Returns a Credential Descriptor (anything except the public key).
     *
     * @return \Webauthn\PublicKeyCredentialDescriptor
     */
    public function toCredentialDescriptor(): CredentialDescriptor
    {
        return $this->toCredentialSource()->getPublicKeyCredentialDescriptor();
    }
}

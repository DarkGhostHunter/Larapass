<?php

namespace DarkGhostHunter\Larapass\Eloquent;

use Webauthn\PublicKeyCredentialUserEntity as UserEntity;
use Webauthn\PublicKeyCredentialSource as CredentialSource;
use Webauthn\PublicKeyCredentialDescriptor as CredentialDescriptor;

trait ManagesCredentialRepository
{
    /**
     * Finds a source of the credentials.
     *
     * @param  string  $id
     * @return null|\Webauthn\PublicKeyCredentialSource
     */
    public function findOneByCredentialId(string $id) : ?CredentialSource
    {
        return optional($this->find($id))->toCredentialSource();
    }

    /**
     * Return an array of all credentials for a given user.
     *
     * @param  \Webauthn\PublicKeyCredentialUserEntity  $entity
     * @return array|\Webauthn\PublicKeyCredentialSource[]
     */
    public function findAllForUserEntity(UserEntity $entity) : array
    {
        return static::where('user_handle', $entity->getId())->get()->map->toCredentialSource()->all();
    }

    /**
     * Update the credentials source into the storage.
     *
     * @param  \Webauthn\PublicKeyCredentialSource  $source
     */
    public function saveCredentialSource(CredentialSource $source) : void
    {
        // We will only update the credential counter, and only if it exists
        if ($model = static::find($source->getPublicKeyCredentialId())) {
            $model->setAttribute('counter', $source->getCounter())->save();
        }
    }

    /**
     * Creates a new Eloquent Model from a Credential Source.
     *
     * @param  \Webauthn\PublicKeyCredentialSource  $source
     * @return self
     */
    public static function fromCredentialSource(CredentialSource $source)
    {
        return ($model = new static)->fill([
            $model->getKeyName()    => Base64Url::encode($source->getPublicKeyCredentialId()),
            'user_handle'           => $source->getUserHandle(),
            'type'                  => $source->getType(),
            'transports'            => $source->getTransports(),
            'attestation_type'      => $source->getAttestationType(),
            'trust_path'            => $source->getTrustPath()->jsonSerialize(),
            'aaguid'                => $source->getAaguid()->toString(),
            'public_key'            => Base64Url::encode($source->getCredentialPublicKey()),
            'counter'               => $source->getCounter(),
        ]);
    }

    /**
     * Transform the current Eloquent model to a Credential Source.
     *
     * @return \Webauthn\PublicKeyCredentialSource
     */
    public function toCredentialSource() : CredentialSource
    {
        return new CredentialSource(
            $this->id,
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
    public function toCredentialDescriptor() : CredentialDescriptor
    {
        return $this->toCredentialSource()->getPublicKeyCredentialDescriptor();
    }
}

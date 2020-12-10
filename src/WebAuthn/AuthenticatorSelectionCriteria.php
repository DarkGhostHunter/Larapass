<?php

namespace DarkGhostHunter\Larapass\WebAuthn;

use Webauthn\AuthenticatorSelectionCriteria as WebAuthnAuthenticatorSelectionCriteria;

class AuthenticatorSelectionCriteria extends WebAuthnAuthenticatorSelectionCriteria
{
    private $residentKey;

    /**
     * Sets the Resident Key variable.
     *
     * @param  string  $type
     */
    public function setResidentKey(?string $type) : WebAuthnAuthenticatorSelectionCriteria
    {
        if (! in_array($type, [self::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            self::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            self::USER_VERIFICATION_REQUIREMENT_DISCOURAGED], false)) {
            throw new \RuntimeException("The {$type} as Resident Key option is unsupported.");
        }

        $this->residentKey = $type;

        return $this;
    }

    public function getResidentKey() : ?string
    {
        return $this->residentKey;
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize() : array
    {
        $serialied = parent::jsonSerialize();

        if (null !== $this->residentKey) {
            $serialied['residentKey'] = $this->residentKey;
        }

        return $serialied;
    }
}
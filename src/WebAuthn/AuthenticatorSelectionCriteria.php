<?php

namespace DarkGhostHunter\Larapass\WebAuthn;

use RuntimeException;
use Webauthn\AuthenticatorSelectionCriteria as WebAuthnAuthenticatorSelectionCriteria;

class AuthenticatorSelectionCriteria extends WebAuthnAuthenticatorSelectionCriteria
{
    private ?string $residentKey = null;

    /**
     * Sets the Resident Key variable.
     *
     * @param  string|null  $residentKey
     *
     * @return \DarkGhostHunter\Larapass\WebAuthn\AuthenticatorSelectionCriteria
     */
    public function setResidentKey(?string $residentKey): AuthenticatorSelectionCriteria
    {
        if (!in_array(
            $residentKey,
            [
                self::RESIDENT_KEY_REQUIREMENT_REQUIRED,
                self::RESIDENT_KEY_REQUIREMENT_PREFERRED,
                self::RESIDENT_KEY_REQUIREMENT_DISCOURAGED,
            ],
            false
        )) {
            throw new RuntimeException("The {$residentKey} as Resident Key option is unsupported.");
        }

        $this->residentKey = $residentKey;

        return $this;
    }

    public function getResidentKey(): ?string
    {
        return $this->residentKey;
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        $serialied = parent::jsonSerialize();

        if (null !== $this->residentKey) {
            $serialied['residentKey'] = $this->residentKey;
        }

        return $serialied;
    }
}

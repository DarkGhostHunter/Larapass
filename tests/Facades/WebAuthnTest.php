<?php

namespace Tests\Facades;

use RuntimeException;
use Tests\RegistersPackage;
use Orchestra\Testbench\TestCase;
use Tests\Stubs\TestWebAuthnUser;
use Tests\RunsPublishableMigrations;
use DarkGhostHunter\Larapass\Facades\WebAuthn;
use DarkGhostHunter\Larapass\WebAuthn\WebAuthnAttestCreator;
use DarkGhostHunter\Larapass\WebAuthn\WebAuthnAttestValidator;
use DarkGhostHunter\Larapass\WebAuthn\WebAuthnAssertValidator;

class WebAuthnTest extends TestCase
{
    use RegistersPackage,
        RunsPublishableMigrations;

    public function test_exception_when_calling_any_method()
    {
        $this->expectException(RuntimeException::class);

        WebAuthn::anyMethod();
    }

    public function test_returns_attestation()
    {
        $user = TestWebAuthnUser::make();

        $this->mock(WebAuthnAttestCreator::class)
            ->shouldReceive('generateAttestation')
            ->with($user)
            ->andReturnTrue();

        $result = WebAuthn::generateAttestation($user);

        $this->assertTrue($result);
    }

    public function test_validates_attestation()
    {
        $user = TestWebAuthnUser::make();

        $array = ['foo' => 'bar'];

        $this->mock(WebAuthnAttestValidator::class)
            ->shouldReceive('validate')
            ->with($array, $user)
            ->andReturnTrue();

        $result = WebAuthn::validateAttestation($array, $user);

        $this->assertTrue($result);
    }

    public function test_creates_assert()
    {
        $user = TestWebAuthnUser::make();

        $this->mock(WebAuthnAssertValidator::class)
            ->shouldReceive('generateAssertion')
            ->with($user)
            ->andReturnTrue();

        $result = WebAuthn::generateAssertion($user);

        $this->assertTrue($result);
    }

    public function test_creates_blank_assert()
    {
        $this->mock(WebAuthnAssertValidator::class)
            ->shouldReceive('generateAssertion')
            ->withNoArgs()
            ->andReturnTrue();

        $result = WebAuthn::generateBlankAssertion();

        $this->assertTrue($result);
    }

    public function test_validates_assert()
    {
        $array = ['foo' => 'bar'];

        $this->mock(WebAuthnAssertValidator::class)
            ->shouldReceive('validate')
            ->with($array)
            ->andReturnTrue();

        $result = WebAuthn::validateAssertion($array);

        $this->assertTrue($result);
    }
}
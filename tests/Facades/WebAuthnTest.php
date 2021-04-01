<?php

namespace Tests\Facades;

use DarkGhostHunter\Larapass\Facades\WebAuthn;
use DarkGhostHunter\Larapass\WebAuthn\WebAuthnAssertValidator;
use DarkGhostHunter\Larapass\WebAuthn\WebAuthnAttestValidator;
use Orchestra\Testbench\TestCase;
use RuntimeException;
use Tests\RegistersPackage;
use Tests\RunsPublishableMigrations;
use Tests\Stubs\TestWebAuthnUser;

class WebAuthnTest extends TestCase
{
    use RegistersPackage,
        RunsPublishableMigrations;

    public function test_exception_when_calling_any_method()
    {
        $this->expectException(RuntimeException::class);

        WebAuthn::anyMethod();
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

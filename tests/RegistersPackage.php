<?php

namespace Tests;

use DarkGhostHunter\Larapass\LarapassServiceProvider;

trait RegistersPackage
{
    protected function getPackageProviders($app)
    {
        return [LarapassServiceProvider::class];
    }
}

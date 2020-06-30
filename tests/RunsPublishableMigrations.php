<?php

namespace Tests;

trait RunsPublishableMigrations
{
    protected function runPublishableMigration()
    {
        $this->loadMigrationsFrom([
                '--realpath' => true,
                '--path' => [
                    realpath(__DIR__ . '/../database/migrations')
                ]
        ]);
    }
}

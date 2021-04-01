<?php

namespace DarkGhostHunter\Larapass\Eloquent\Casting;

use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Ramsey\Uuid\Uuid;

class UuidCast implements CastsAttributes
{
    /**
     * Transform the attribute from the underlying model values.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $key
     * @param  mixed  $value
     * @param  array  $attributes
     *
     * @return \Ramsey\Uuid\UuidInterface
     */
    public function get($model, string $key, $value, array $attributes): \Ramsey\Uuid\UuidInterface
    {
        return Uuid::fromString($value);
    }

    /**
     * Transform the attribute to its underlying model values.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $key
     * @param  mixed  $value
     * @param  array  $attributes
     *
     * @return array|string
     */
    public function set($model, string $key, $value, array $attributes)
    {
        return (mb_strlen($value, '8bit') === 36
            ? Uuid::fromString($value)
            : Uuid::fromBytes(base64_decode($value, true)))->toString();
    }
}

<?php

namespace DarkGhostHunter\Larapass\Eloquent\Casting;

use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Webauthn\TrustPath\TrustPathLoader;

class TrustPathCast implements CastsAttributes
{
    /**
     * Transform the attribute from the underlying model values.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $key
     * @param  mixed  $value
     * @param  array  $attributes
     *
     * @return \Webauthn\TrustPath\TrustPath
     */
    public function get($model, string $key, $value, array $attributes): \Webauthn\TrustPath\TrustPath
    {
        return TrustPathLoader::loadTrustPath(json_decode($value, true));
    }

    /**
     * Transform the attribute to its underlying model values.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $key
     * @param  \Webauthn\TrustPath\TrustPath|array  $value
     * @param  array  $attributes
     *
     * @return string
     */
    public function set($model, string $key, $value, array $attributes): string
    {
        return json_encode($value);
    }
}

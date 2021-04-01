<?php

namespace DarkGhostHunter\Larapass\Eloquent\Casting;

use Base64Url\Base64Url;
use Illuminate\Contracts\Database\Eloquent\CastsAttributes;

class Base64UrlCast implements CastsAttributes
{
    /**
     * Transform the attribute from the underlying model values.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $key
     * @param  mixed  $value
     * @param  array  $attributes
     *
     * @return string
     */
    public function get($model, string $key, $value, array $attributes): string
    {
        return Base64Url::decode($value);
    }

    /**
     * Transform the attribute to its underlying model values.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $key
     * @param  mixed  $value
     * @param  array  $attributes
     *
     * @return string
     */
    public function set($model, string $key, $value, array $attributes): string
    {
        return Base64Url::encode($value);
    }
}

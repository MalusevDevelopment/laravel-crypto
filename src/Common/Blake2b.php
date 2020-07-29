<?php


namespace BrosSquad\LaravelHashing\Common;


use SodiumException;
use BrosSquad\LaravelHashing\Facades\Base64;

/**
 * Class Blake2b
 *
 * @package BrosSquad\LaravelHashing\Common
 */
class Blake2b extends Hash
{

    /**
     * @param  string  $data
     *
     * @return string|null
     */
    public function hash(string $data): ?string
    {
        return Base64::constantUrlEncodeNoPadding($this->hashRaw($data));
    }

    public function hashRaw(string $data): ?string
    {
        try {
            return sodium_crypto_generichash($data, '', 64);
        } catch (SodiumException $e) {
            return null;
        }
    }
}

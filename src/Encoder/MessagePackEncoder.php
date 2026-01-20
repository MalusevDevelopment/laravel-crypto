<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Encoder;

use CodeLieutenant\LaravelCrypto\Contracts\Encoder;
use RuntimeException;

class MessagePackEncoder implements Encoder
{
    public function __construct()
    {
        throw_unless(extension_loaded('msgpack'), RuntimeException::class, 'msgpack extension is not loaded');
    }

    public function encode(mixed $value): string
    {
        return msgpack_serialize($value);
    }

    public function decode(string $value): mixed
    {
        return msgpack_unserialize($value);
    }
}

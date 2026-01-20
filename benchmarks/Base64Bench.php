<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Benchmarks;

use CodeLieutenant\LaravelCrypto\Support\Base64;
use Generator;
use PhpBench\Attributes\Groups;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\ParamProviders;
use PhpBench\Attributes\Revs;
use PhpBench\Attributes\Sleep;
use PhpBench\Attributes\Warmup;

class Base64Bench
{
    #[ParamProviders('randomData')]
    #[Iterations(3)]
    #[Warmup(2)]
    #[Sleep(100)]
    #[Revs(2000)]
    #[Groups(['encode'])]
    public function benchPhpBase64Encode(array $data): void
    {
        $encoded = base64_encode($data[0]);
        unset($encoded);
    }

    #[ParamProviders('randomData')]
    #[Iterations(3)]
    #[Warmup(2)]
    #[Sleep(100)]
    #[Revs(2000)]
    #[Groups(['encode-no-padding'])]
    public function benchPhpBase64EncodeNoPadding(array $data): void
    {
        $encoded = rtrim(base64_encode($data[0]), '=');
        unset($encoded);
    }

    #[ParamProviders('randomData')]
    #[Iterations(3)]
    #[Warmup(2)]
    #[Sleep(100)]
    #[Revs(2000)]
    #[Groups(['encode-url'])]
    public function benchPhpBase64UrlEncode(array $data): void
    {
        $encoded = str_replace(['+', '/'], ['-', '_'], base64_encode($data[0]));
        unset($encoded);
    }

    #[ParamProviders('randomData')]
    #[Iterations(3)]
    #[Warmup(2)]
    #[Sleep(100)]
    #[Revs(2000)]
    #[Groups(['encode-url-no-padding'])]
    public function benchPhpBase64UrlEncodeNoPadding(array $data): void
    {
        $encoded = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data[0]));
        unset($encoded);
    }

    #[ParamProviders('randomData')]
    #[Iterations(3)]
    #[Warmup(2)]
    #[Sleep(100)]
    #[Revs(2000)]
    #[Groups(['encode'])]
    public function benchPhpBase64EncodeWithHelper(array $data): void
    {
        $encoded = Base64::encode($data[0]);
        unset($encoded);
    }

    #[ParamProviders('randomData')]
    #[Iterations(3)]
    #[Warmup(2)]
    #[Sleep(100)]
    #[Revs(2000)]
    #[Groups(['encode-no-padding'])]
    public function benchPhpBase64EncodeNoPaddingWithHelper(array $data): void
    {
        $encoded = Base64::encodeNoPadding($data[0]);
        unset($encoded);
    }

    #[ParamProviders('randomData')]
    #[Iterations(3)]
    #[Warmup(2)]
    #[Sleep(100)]
    #[Revs(2000)]
    #[Groups(['encode-url'])]
    public function benchPhpBase64UrlEncodeWithHelper(array $data): void
    {
        $encoded = Base64::urlEncode($data[0]);
        unset($encoded);
    }

    #[ParamProviders('randomData')]
    #[Iterations(3)]
    #[Warmup(2)]
    #[Sleep(100)]
    #[Revs(2000)]
    #[Groups(['encode-url-no-padding'])]
    public function benchPhpBase64UrlEncodeNoPaddingWithHelper(array $data): void
    {
        $encoded = Base64::urlEncodeNoPadding($data[0]);
        unset($encoded);
    }

    #[ParamProviders('randomData')]
    #[Iterations(3)]
    #[Warmup(2)]
    #[Sleep(100)]
    #[Revs(2000)]
    #[Groups(['encode'])]
    public function benchConstantTimeBase64EncodeWithHelper(array $data): void
    {
        $encoded = Base64::constantEncode($data[0]);
        unset($encoded);
    }

    #[ParamProviders('randomData')]
    #[Iterations(3)]
    #[Warmup(2)]
    #[Sleep(100)]
    #[Revs(2000)]
    #[Groups(['encode-no-padding'])]
    public function benchConstantTimeBase64EncodeNoPaddingWithHelper(array $data): void
    {
        $encoded = Base64::constantEncodeNoPadding($data[0]);
        unset($encoded);
    }

    #[ParamProviders('randomData')]
    #[Iterations(3)]
    #[Warmup(2)]
    #[Sleep(100)]
    #[Revs(2000)]
    #[Groups(['encode-url'])]
    public function benchConstantTimeBase64UrlEncodeWithHelper(array $data): void
    {
        $encoded = Base64::constantUrlEncode($data[0]);
        unset($encoded);
    }

    #[ParamProviders('randomData')]
    #[Iterations(3)]
    #[Warmup(2)]
    #[Sleep(100)]
    #[Revs(2000)]
    #[Groups(['encode-url-no-padding'])]
    public function benchConstantTimeBase64UrlEncodeNoPaddingWithHelper(array $data): void
    {
        $encoded = Base64::constantUrlEncodeNoPadding($data[0]);
        unset($encoded);
    }

    //
    //    #[ParamProviders('encodedDataBase64')]
    //    #[Iterations(3)]
    //    #[Warmup(2)]
    //    #[Sleep(100)]
    //    #[Revs(2000)]
    //    public function benchDecode(array $data): void
    //    {
    //        $decoded = base64_decode($data[0]);
    //        unset($decoded);
    //    }
    //
    //    #[ParamProviders('encodedDataBase64NoPadding')]
    //    #[Iterations(3)]
    //    #[Warmup(2)]
    //    #[Sleep(100)]
    //    #[Revs(2000)]
    //    public function benchDecodeNoPadding(array $data): void
    //    {
    //        $decoded = base64_decode($data[0]);
    //        unset($decoded);
    //    }
    //    #[ParamProviders('encodedDataBase64Url')]
    //    #[Iterations(3)]
    //    #[Warmup(2)]
    //    #[Sleep(100)]
    //    #[Revs(2000)]
    //    public function benchUrlDecode(array $data): void
    //    {
    //        $decoded = base64_decode(str_replace(['-', '_'], ['+', '/'], $data[0]));
    //        unset($decoded);
    //    }
    //    #[ParamProviders('encodedDataBase64UrlNoPadding')]
    //    #[Iterations(3)]
    //    #[Warmup(2)]
    //    #[Sleep(100)]
    //    #[Revs(2000)]
    //    public function benchUrlDecodeNoPadding(array $data): void
    //    {
    //        $decoded = base64_decode(str_replace(['-', '_'], ['+', '/'], $data[0]));
    //        unset($decoded);
    //    }
    //
    //    #[ParamProviders('encodedDataBase64')]
    //    #[Iterations(3)]
    //    #[Warmup(2)]
    //    #[Sleep(100)]
    //    #[Revs(2000)]
    //    public function benchDecodeWithHelper(array $data): void
    //    {
    //        $decoded = Base64::decode($data[0]);
    //        unset($decoded);
    //    }
    //
    //    #[ParamProviders('encodedDataBase64NoPadding')]
    //    #[Iterations(3)]
    //    #[Warmup(2)]
    //    #[Sleep(100)]
    //    #[Revs(2000)]
    //    public function benchDecodeNoPaddingWithHelper(array $data): void
    //    {
    //        $decoded = Base64::decode($data[0]);
    //        unset($decoded);
    //    }
    //    #[ParamProviders('encodedDataBase64Url')]
    //    #[Iterations(3)]
    //    #[Warmup(2)]
    //    #[Sleep(100)]
    //    #[Revs(2000)]
    //    public function benchDecodeUrlWithHelper(array $data): void
    //    {
    //        $decoded = Base64::urlDecode($data[0]);
    //        unset($decoded);
    //    }
    //
    //    #[ParamProviders('encodedDataBase64UrlNoPadding')]
    //    #[Iterations(3)]
    //    #[Warmup(2)]
    //    #[Sleep(100)]
    //    #[Revs(2000)]
    //    public function benchDecodeUrlNoPaddingWithHelper(array $data): void
    //    {
    //        $decoded = Base64::urlDecode($data[0]);
    //        unset($decoded);
    //    }

    public function encodedDataBase64(): Generator
    {
        yield [base64_encode(random_bytes(16))];
        yield [base64_encode(random_bytes(32))];
        yield [base64_encode(random_bytes(48))];
        yield [base64_encode(random_bytes(64))];
        yield [base64_encode(random_bytes(128))];
        yield [base64_encode(random_bytes(256))];
        yield [base64_encode(random_bytes(1024))];
        yield [base64_encode(random_bytes(2048))];
        yield [base64_encode(random_bytes(4096))];
        yield [base64_encode(random_bytes(8192))];
    }

    public function encodedDataBase64NoPadding(): Generator
    {
        yield [rtrim(base64_encode(random_bytes(16)), '=')];
        yield [rtrim(base64_encode(random_bytes(32)), '=')];
        yield [rtrim(base64_encode(random_bytes(48)), '=')];
        yield [rtrim(base64_encode(random_bytes(64)), '=')];
        yield [rtrim(base64_encode(random_bytes(128)), '=')];
        yield [rtrim(base64_encode(random_bytes(256)), '=')];
        yield [rtrim(base64_encode(random_bytes(1024)), '=')];
        yield [rtrim(base64_encode(random_bytes(2048)), '=')];
        yield [rtrim(base64_encode(random_bytes(4096)), '=')];
        yield [rtrim(base64_encode(random_bytes(8192)), '=')];
    }

    public function encodedDataBase64Url(): Generator
    {
        yield [str_replace(['+', '/'], ['-', '_'], base64_encode(random_bytes(16)))];
        yield [str_replace(['+', '/'], ['-', '_'], base64_encode(random_bytes(32)))];
        yield [str_replace(['+', '/'], ['-', '_'], base64_encode(random_bytes(48)))];
        yield [str_replace(['+', '/'], ['-', '_'], base64_encode(random_bytes(64)))];
        yield [str_replace(['+', '/'], ['-', '_'], base64_encode(random_bytes(128)))];
        yield [str_replace(['+', '/'], ['-', '_'], base64_encode(random_bytes(256)))];
        yield [str_replace(['+', '/'], ['-', '_'], base64_encode(random_bytes(1024)))];
        yield [str_replace(['+', '/'], ['-', '_'], base64_encode(random_bytes(2048)))];
        yield [str_replace(['+', '/'], ['-', '_'], base64_encode(random_bytes(4096)))];
        yield [str_replace(['+', '/'], ['-', '_'], base64_encode(random_bytes(8192)))];
    }

    public function encodedDataBase64UrlNoPadding(): Generator
    {
        yield [str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(random_bytes(16)))];
        yield [str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(random_bytes(32)))];
        yield [str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(random_bytes(48)))];
        yield [str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(random_bytes(64)))];
        yield [str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(random_bytes(128)))];
        yield [str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(random_bytes(256)))];
        yield [str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(random_bytes(1024)))];
        yield [str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(random_bytes(2048)))];
        yield [str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(random_bytes(4096)))];
        yield [str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(random_bytes(8192)))];
    }

    public function randomData(): Generator
    {
        yield [random_bytes(2)];
        yield [random_bytes(16)];
        yield [random_bytes(32)];
        yield [random_bytes(48)];
        yield [random_bytes(64)];
        yield [random_bytes(128)];
        yield [random_bytes(256)];
        yield [random_bytes(1024)];
        yield [random_bytes(2048)];
        yield [random_bytes(4096)];
        yield [random_bytes(8192)];
        //        yield [random_bytes(1024 * 1024)];
    }
}

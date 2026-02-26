<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Contracts;

use SensitiveParameter;

interface FileEncrypter
{
    public function encryptFile(#[SensitiveParameter] string $key, string $inputFilePath, string $outputFilePath): void;

    public function decryptFile(#[SensitiveParameter] string $key, string $inputFilePath, string $outputFilePath): void;
}

<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Traits\EnvKeySaver;
use Illuminate\Support\Facades\File;

$class = new class
{
    use EnvKeySaver {
        writeNewEnvironmentFileWith as public;
        keyReplacementPattern as public;
        formatKey as public;
    }
};

beforeEach(function () {
    $this->tempEnvFile = tempnam(sys_get_temp_dir(), 'env_test_');
    File::put($this->tempEnvFile, "EXISTING_KEY=old_value\n");
});

afterEach(function () {
    if (File::exists($this->tempEnvFile)) {
        File::delete($this->tempEnvFile);
    }
});

test('it replaces existing key', function () use ($class) {
    $class->writeNewEnvironmentFileWith($this->tempEnvFile, [
        'EXISTING_KEY' => ['old' => 'old_value', 'new' => 'new_value'],
    ]);

    expect(File::get($this->tempEnvFile))->toContain('EXISTING_KEY=new_value')
        ->and(File::get($this->tempEnvFile))->not->toContain('EXISTING_KEY=old_value');
});

test('it appends if key not found', function () use ($class) {
    $class->writeNewEnvironmentFileWith($this->tempEnvFile, [
        'NEW_KEY' => ['old' => 'non_existent', 'new' => 'new_value'],
    ]);

    expect(File::get($this->tempEnvFile))->toContain('EXISTING_KEY=old_value')
        ->and(File::get($this->tempEnvFile))->toContain('NEW_KEY=new_value');
});

test('it handles array old values', function () use ($class) {
    File::put($this->tempEnvFile, "APP_PREVIOUS_KEYS=key1,key2\n");
    $class->writeNewEnvironmentFileWith($this->tempEnvFile, [
        'APP_PREVIOUS_KEYS' => ['old' => ['key1', 'key2'], 'new' => 'key0,key1,key2'],
    ]);

    expect(File::get($this->tempEnvFile))->toContain('APP_PREVIOUS_KEYS=key0,key1,key2');
});

test('it throws on non-existent file', function () use ($class) {
    expect(fn () => $class->writeNewEnvironmentFileWith('/non/existent/path', []))
        ->toThrow(RuntimeException::class, 'Error while reading environment file');
});

test('formatKey', function () use ($class) {
    expect($class->formatKey('test'))->toBe('base64:'.base64_encode('test'));
});

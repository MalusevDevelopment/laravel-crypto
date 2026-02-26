<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Tests\Feature\Casts;

use CodeLieutenant\LaravelCrypto\Casts\EncryptedFileCast;
use CodeLieutenant\LaravelCrypto\Support\EncryptedFile;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Schema;

class TestModel extends Model
{
    protected $table = 'test_models';

    protected $casts = [
        'file' => EncryptedFileCast::class,
    ];

    protected $fillable = ['file'];
}

test('it can encrypt and decrypt a file through the caster', function () {
    Schema::create('test_models', function (Blueprint $table) {
        $table->id();
        $table->string('file')->nullable();
        $table->timestamps();
    });

    $plainPath = tempnam(sys_get_temp_dir(), 'plain');
    file_put_contents($plainPath, 'Hello World');

    $encryptedPath = sys_get_temp_dir().'/encrypted_'.uniqid();

    // Create a new model and set the file using EncryptedFile object
    $model = new TestModel;
    $encryptedFile = new EncryptedFile($encryptedPath);
    $encryptedFile->setDecryptedPath($plainPath);

    $model->file = $encryptedFile;
    $model->save();

    // Verify file is encrypted
    expect(file_exists($encryptedPath))->toBeTrue();
    expect(file_get_contents($encryptedPath))->not->toBe('Hello World');

    // Clear model from memory and retrieve from DB
    $model = TestModel::find($model->id);

    expect($model->file)->toBeInstanceOf(EncryptedFile::class);
    expect($model->file->getEncryptedPath())->toBe($encryptedPath);

    $decryptedPath = $model->file->getDecryptedPath();
    expect(file_get_contents($decryptedPath))->toBe('Hello World');

    // Clean up
    if (file_exists($plainPath)) {
        unlink($plainPath);
    }
    if (file_exists($encryptedPath)) {
        unlink($encryptedPath);
    }
});

test('it re-encrypts the file when content changes', function () {
    Schema::create('test_models', function (Blueprint $table) {
        $table->id();
        $table->string('file')->nullable();
        $table->timestamps();
    });

    $encryptedPath = tempnam(sys_get_temp_dir(), 'encrypted');

    // Initial save
    $plainPath = tempnam(sys_get_temp_dir(), 'plain');
    file_put_contents($plainPath, 'Initial Content');
    Crypt::encryptFile($plainPath, $encryptedPath);
    unlink($plainPath);

    $model = TestModel::create(['file' => $encryptedPath]);

    // Modify decrypted content
    $decryptedPath = $model->file->getDecryptedPath();
    file_put_contents($decryptedPath, 'Updated Content');

    $model->save();

    // Retrieve again and verify
    $model = TestModel::find($model->id);
    $newDecryptedPath = $model->file->getDecryptedPath();
    expect(file_get_contents($newDecryptedPath))->toBe('Updated Content');

    // Clean up
    if (file_exists($encryptedPath)) {
        unlink($encryptedPath);
    }
});

test('it re-encrypts/moves the file when path changes', function () {
    Schema::create('test_models', function (Blueprint $table) {
        $table->id();
        $table->string('file')->nullable();
        $table->timestamps();
    });

    $oldEncryptedPath = tempnam(sys_get_temp_dir(), 'old_encrypted');
    $newEncryptedPath = sys_get_temp_dir().'/new_encrypted_'.uniqid();

    $plainPath = tempnam(sys_get_temp_dir(), 'plain');
    file_put_contents($plainPath, 'Persistent Content');
    Crypt::encryptFile($plainPath, $oldEncryptedPath);
    unlink($plainPath);

    $model = TestModel::create(['file' => $oldEncryptedPath]);

    // Change encrypted path
    $model->file->setEncryptedPath($newEncryptedPath);
    $model->save();

    expect(file_exists($newEncryptedPath))->toBeTrue();
    // Verify it's encrypted and has correct content
    $decPath = tempnam(sys_get_temp_dir(), 'dec');
    Crypt::decryptFile($newEncryptedPath, $decPath);
    expect(file_get_contents($decPath))->toBe('Persistent Content');

    // Clean up
    if (file_exists($oldEncryptedPath)) {
        unlink($oldEncryptedPath);
    }
    if (file_exists($newEncryptedPath)) {
        unlink($newEncryptedPath);
    }
    if (file_exists($decPath)) {
        unlink($decPath);
    }
});

test('it can use helper methods to read and write content', function () {
    Schema::create('test_models', function (Blueprint $table) {
        $table->id();
        $table->string('file')->nullable();
        $table->timestamps();
    });

    $encryptedPath = sys_get_temp_dir().'/encrypted_'.uniqid();

    $model = TestModel::create(['file' => $encryptedPath]);

    $model->file->putContents('Helper Content');
    $model->save();

    // Retrieve and verify
    $model = TestModel::find($model->id);
    expect($model->file->contents())->toBe('Helper Content');

    // Test stream
    $stream = $model->file->stream();
    expect(stream_get_contents($stream))->toBe('Helper Content');
    fclose($stream);

    // Clean up
    if (file_exists($encryptedPath)) {
        unlink($encryptedPath);
    }
});

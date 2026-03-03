<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('users', static function (Blueprint $table): void {
            $table->id();
            $table->string('name');
            $table->string('email')->unique();
            $table->string('password');
            // Per-user encryption blob: version(1)+salt(16)+nonce(24)+ciphertext(32)+tag(16) = 89 bytes max
            $table->binary('encryption_key', length: 89)->nullable();
            $table->text('secret_note')->nullable();
            $table->text('ssn')->nullable();
            // Blind index for SSN — enables WHERE ssn_index = ? without decryption
            $table->blindIndex('ssn')->nullable()->index();
            // JSON-encrypted columns
            $table->text('medical_history')->nullable();
            $table->text('address')->nullable();
            // JSON-encrypted + blind-indexed on the 'email' sub-key
            $table->text('profile')->nullable();
            $table->blindIndex('profile_email')->nullable()->index();
            $table->rememberToken();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('users');
    }
};

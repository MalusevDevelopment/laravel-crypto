<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Adds the per-user encryption_key column to the users table.
 *
 *   encryption_key  binary(89)   Self-contained versioned blob.
 *
 *   Version 0x01 (password-wrapped, 89 bytes):
 *     0x01 || salt(16) || nonce(24) || XChaCha20-Poly1305(key=32, tag=16)
 *
 *   Version 0x02 (server-wrapped, 73 bytes):
 *     0x02 || nonce(24) || XChaCha20-Poly1305(key=32, tag=16)
 *
 * Nullable — existing users are auto-enrolled on first login.
 */
return new class extends Migration
{
    public function up(): void
    {
        if (! Schema::hasTable('users') || Schema::hasColumn('users', 'encryption_key')) {
            return;
        }

        Schema::table('users', static function (Blueprint $table): void {
            $table->binary('encryption_key', length: 89)->nullable()->after('password');
        });
    }

    public function down(): void
    {
        if (! Schema::hasTable('users') || ! Schema::hasColumn('users', 'encryption_key')) {
            return;
        }

        Schema::table('users', static function (Blueprint $table): void {
            $table->dropColumn('encryption_key');
        });
    }
};


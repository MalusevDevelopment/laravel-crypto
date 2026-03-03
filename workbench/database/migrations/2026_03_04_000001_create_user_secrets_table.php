<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('user_secrets', static function (Blueprint $table): void {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->string('label');
            $table->text('secret_value');
            $table->blindIndex('secret_value');
            $table->timestamps();

            // Unique combination: for a given user, a label + encrypted value must be unique
            $table->unique(['user_id', 'label', 'secret_value_index']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('user_secrets');
    }
};

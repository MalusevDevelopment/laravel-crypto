<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Casts\UserEncryptedWithIndex;
use CodeLieutenant\LaravelCrypto\Traits\HasUserEncryption;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class TenantUser extends Model
{
    use HasUserEncryption;

    protected $table = 'tenant_users';

    protected $guarded = [];

    protected function casts(): array
    {
        return [
            'email' => UserEncryptedWithIndex::class.':email_index,true,global,tenant_id',
        ];
    }
}

use CodeLieutenant\LaravelCrypto\Casts\UserEncryptedJsonWithIndex;
use CodeLieutenant\LaravelCrypto\Contracts\UserEncryptionContext as UserEncryptionContextContract;

class TenantUserWithJson extends Model
{
    use HasUserEncryption;

    protected $table = 'tenant_users_json';

    protected $guarded = [];

    protected function casts(): array
    {
        return [
            'profile' => UserEncryptedJsonWithIndex::class.':profile_email_index,email,array,true,global,tenant_id',
        ];
    }
}

describe('Unique/Composite Blind Indexes', function (): void {
    beforeEach(function (): void {
        Schema::create('tenant_users', function (Blueprint $table) {
            $table->id();
            $table->integer('tenant_id');
            $table->text('email');
            $table->binary('email_index', 32);
            $table->unique(['tenant_id', 'email_index']);
            $table->timestamps();
        });

        Schema::create('tenant_users_json', function (Blueprint $table) {
            $table->id();
            $table->integer('tenant_id');
            $table->text('profile');
            $table->binary('profile_email_index', 32);
            $table->unique(['tenant_id', 'profile_email_index']);
            $table->timestamps();
        });
    });

    afterEach(function (): void {
        Schema::dropIfExists('tenant_users');
        Schema::dropIfExists('tenant_users_json');
        app(UserEncryptionContextContract::class)->clear();
    });

    test('it can compute a global blind index with context (composite unique)', function (): void {
        $userKey = random_bytes(32);
        app(UserEncryptionContextContract::class)->set($userKey);

        TenantUser::create([
            'tenant_id' => 1,
            'email' => 'alice@example.com',
        ]);

        // This should pass (different tenant)
        TenantUser::create([
            'tenant_id' => 2,
            'email' => 'alice@example.com',
        ]);

        expect(TenantUser::count())->toBe(2);

        // This should fail (same tenant, same email)
        expect(fn () => TenantUser::create([
            'tenant_id' => 1,
            'email' => 'alice@example.com',
        ]))->toThrow(Illuminate\Database\QueryException::class);
    });

    test('it can search by global blind index with context', function (): void {
        $userKey = random_bytes(32);
        app(UserEncryptionContextContract::class)->set($userKey);

        TenantUser::create(['tenant_id' => 1, 'email' => 'alice@example.com']);
        TenantUser::create(['tenant_id' => 2, 'email' => 'alice@example.com']);
        TenantUser::create(['tenant_id' => 1, 'email' => 'bob@example.com']);

        $found = TenantUser::whereUserEncrypted(
            column: 'email',
            value: 'alice@example.com',
            mode: 'global',
            context: ['1'] // tenant_id = 1
        )->first();

        expect($found)->not->toBeNull();
        expect($found->tenant_id)->toBe(1);
        expect($found->email)->toBe('alice@example.com');

        $found2 = TenantUser::whereUserEncrypted(
            column: 'email',
            value: 'alice@example.com',
            mode: 'global',
            context: ['2'] // tenant_id = 2
        )->first();

        expect($found2)->not->toBeNull();
        expect($found2->tenant_id)->toBe(2);
    });

    test('it can compute a global blind index for JSON fields with context', function (): void {
        $userKey = random_bytes(32);
        app(UserEncryptionContextContract::class)->set($userKey);

        TenantUserWithJson::create([
            'tenant_id' => 1,
            'profile' => ['email' => 'alice@example.com'],
        ]);

        // Same email, different tenant — should pass
        TenantUserWithJson::create([
            'tenant_id' => 2,
            'profile' => ['email' => 'alice@example.com'],
        ]);

        expect(TenantUserWithJson::count())->toBe(2);

        // Same email, same tenant — should fail
        expect(fn () => TenantUserWithJson::create([
            'tenant_id' => 1,
            'profile' => ['email' => 'alice@example.com'],
        ]))->toThrow(Illuminate\Database\QueryException::class);
    });
});

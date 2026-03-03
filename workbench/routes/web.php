<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Encryption\UserKey\UserEncrypter;
use CodeLieutenant\LaravelCrypto\Facades\UserCrypt;
use CodeLieutenant\LaravelCrypto\Http\Middleware\BootPerUserEncryption;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use Workbench\App\Models\User;
use Workbench\App\Models\UserSecret;

// ── Public ────────────────────────────────────────────────────────────────

Route::post('/register', static function (Request $request) {
    $user = User::create([
        'name' => $request->input('name', 'Test'),
        'email' => $request->input('email'),
        'password' => Hash::make($request->input('password')),
    ]);

    $rawKey = $user->initUserEncryption($request->input('password'));
    $user->save();

    $token = $user->encodeEncryptionToken($rawKey);

    return response()->json(['id' => $user->id, 'email' => $user->email], 201)
        ->header('X-Encryption-Token', $token);
});

Route::post('/login', static function (Request $request) {
    $user = User::where('email', $request->input('email'))->first();

    if (! $user || ! Hash::check($request->input('password'), $user->password)) {
        return response()->json(['message' => 'Unauthorized'], 401);
    }

    Auth::login($user);

    $token = $user->issueEncryptionToken($request->input('password'));

    return response()->json(['id' => $user->id])->header('X-Encryption-Token', $token);
});

/**
 * Session-only login — does NOT require or issue an encryption token.
 * Simulates a plain web login (Filament / Breeze / Jetstream).
 * The BootPerUserEncryption middleware will auto-enroll the user on the first
 * subsequent authenticated request.
 */
Route::post('/login-session', static function (Request $request) {
    $user = User::where('email', $request->input('email'))->first();

    if (! $user || ! Hash::check($request->input('password'), $user->password)) {
        return response()->json(['message' => 'Unauthorized'], 401);
    }

    Auth::login($user);

    return response()->json(['id' => $user->id]);
});

// ── Authenticated + per-user encryption ──────────────────────────────────

Route::middleware(['auth', BootPerUserEncryption::class])->group(static function (): void {

    Route::post('/profile/secrets', static function (Request $request) {
        $user = Auth::user();
        $user->secret_note = $request->input('secret_note');
        $user->ssn = $request->input('ssn');
        $user->save();

        return response()->json(['ok' => true]);
    });

    Route::get('/profile/secrets', static function () {
        $user = User::findOrFail(Auth::id());

        return response()->json([
            'secret_note' => $user->secret_note,
            'ssn' => $user->ssn,
        ]);
    });

    Route::post('/profile/json', static function (Request $request) {
        $user = Auth::user() ?? throw new RuntimeException('No authenticated user');

        if ($request->has('medical_history')) {
            $user->medical_history = $request->input('medical_history'); // array
        }
        if ($request->has('address')) {
            $user->address = $request->input('address'); // will be stdClass on read
        }
        if ($request->has('profile')) {
            $user->profile = $request->input('profile'); // array + blind-indexed on 'email'
        }

        $user->save();

        return response()->json(['ok' => true]);
    });

    Route::get('/profile/json', static function () {
        $user = User::findOrFail(Auth::id());

        return response()->json([
            'medical_history' => $user->medical_history,
            'address' => (array) $user->address,   // stdClass → array for JSON comparison
            'profile' => $user->profile,
        ]);
    });

    Route::post('/encrypt', static function (Request $request, UserEncrypter $crypt) {
        return response()->json([
            'ciphertext' => $crypt->encrypt($request->input('value')),
        ]);
    });

    Route::post('/decrypt', static function (Request $request, UserEncrypter $crypt) {
        return response()->json([
            'plaintext' => $crypt->decrypt($request->input('ciphertext')),
        ]);
    });

    Route::post('/encrypt-string', static function (Request $request) {
        return response()->json([
            'ciphertext' => UserCrypt::encryptString($request->input('value')),
        ]);
    });

    Route::post('/decrypt-string', static function (Request $request) {
        return response()->json([
            'plaintext' => UserCrypt::decryptString($request->input('ciphertext')),
        ]);
    });

    Route::post('/encrypt-file', static function (Request $request, UserEncrypter $crypt) {
        $input = $request->input('input');
        $output = $request->input('output');
        $crypt->encryptFile($input, $output);

        return response()->json(['ok' => true]);
    });

    Route::post('/decrypt-file', static function (Request $request, UserEncrypter $crypt) {
        $input = $request->input('input');
        $output = $request->input('output');
        $crypt->decryptFile($input, $output);

        return response()->json(['ok' => true]);
    });

    Route::post('/change-password', static function (Request $request) {
        $user = Auth::user();

        $user->rewrapUserEncryption(
            $request->input('current_password'),
            $request->input('new_password'),
        );
        $user->password = Hash::make($request->input('new_password'));
        $user->save();

        $token = $user->issueEncryptionToken($request->input('new_password'));

        return response()->json(['ok' => true])->header('X-Encryption-Token', $token);
    });

    /**
     * Search users by encrypted SSN using the blind index.
     * No SSNs are decrypted during the search — only the index is compared.
     */
    Route::get('/search-by-ssn', static function (Request $request) {
        $ssn = $request->query('ssn');

        $users = User::whereUserEncrypted('ssn', $ssn)->get(['id', 'name', 'email']);

        return response()->json($users);
    });

    /**
     * Compute the blind index for an arbitrary value + column name.
     * Useful for testing / debugging.
     */
    Route::post('/blind-index', static function (Request $request, UserEncrypter $crypt) {
        return response()->json([
            'index' => base64_encode($crypt->blindIndex(
                $request->input('value'),
                $request->input('column'),
            )),
        ]);
    });

    Route::post('/user-secrets', static function (Request $request) {
        $secret = UserSecret::create([
            'user_id' => Auth::id(),
            'label' => $request->input('label'),
            'secret_value' => $request->input('value'),
        ]);

        $data = $secret->makeVisible('secret_value_index')->toArray();
        $data['secret_value_index'] = base64_encode($data['secret_value_index']);

        return response()->json($data, 201);
    });

    Route::get('/user-secrets/search', static function (Request $request) {
        $label = $request->query('label');
        $value = $request->query('value');

        $secrets = UserSecret::where('label', $label)
            ->whereUserEncrypted('secret_value', $value, indexColumn: 'secret_value_index', context: [$label])
            ->get();

        return response()->json($secrets);
    });
});

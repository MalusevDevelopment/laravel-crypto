<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Support\Base64;

it('encodes binary data', function (): void {
    $data = random_bytes(32);

    $encoded = Base64::encode($data);

    expect($encoded)->toBe(base64_encode($data));
});

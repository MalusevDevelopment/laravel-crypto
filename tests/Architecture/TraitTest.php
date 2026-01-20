<?php

declare(strict_types=1);

arch('traits')
    ->expect('CodeLieutenant\LaravelCrypto\Traits')
    ->toBeTraits();

arch('hashing traits')
    ->expect('CodeLieutenant\LaravelCrypto\Hashing\Traits')
    ->toBeTraits();

arch('signing traits')
    ->expect('CodeLieutenant\LaravelCrypto\Signing\Traits')
    ->toBeTraits();

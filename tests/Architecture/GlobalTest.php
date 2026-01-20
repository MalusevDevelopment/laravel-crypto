<?php

declare(strict_types=1);

arch('globals')
    ->expect(['dd', 'dump', 'ray'])
    ->not->toBeUsed();

arch('strict types')
    ->expect('CodeLieutenant\LaravelCrypto')
    ->toUseStrictTypes();

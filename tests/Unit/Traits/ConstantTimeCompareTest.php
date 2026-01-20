<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Tests\Unit\Traits;

use CodeLieutenant\LaravelCrypto\Traits\ConstantTimeCompare;

class ConstantTimeCompareTestClass
{
    use ConstantTimeCompare;
}

test('constant time compare equals', function (): void {
    $test = new ConstantTimeCompareTestClass;

    expect($test->equals('abc', 'abc'))->toBeTrue()
        ->and($test->equals('abc', 'abd'))->toBeFalse()
        ->and($test->equals('abc', 'abcd'))->toBeFalse()
        ->and($test->equals('abcd', 'abc'))->toBeFalse();
});

test('constant time compare prevents padding attack', function (): void {
    $test = new ConstantTimeCompareTestClass;

    // The original implementation would return true for these
    $s1 = "ab\x80";
    $s2 = 'ab';

    expect($test->equals($s1, $s2))->toBeFalse();
});

<?php declare(strict_types = 1);

namespace AES\Padding;

interface Scheme
{
    function getPadding(string $message): string;
    function getPaddingLength(string $message): int;
} 

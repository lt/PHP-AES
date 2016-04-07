<?php declare(strict_types = 1);

namespace AES\Padding;

use AES\Exception\InvalidPaddingException;

class ISOIEC7816 implements Scheme
{
    function getPadding(string $message): string
    {
        $padLen = 16 - (strlen($message) % 16);
        return "\x80" . str_repeat("\0", $padLen - 1);
    }

    function getPaddingLength(string $message): int
    {
        $index = strlen($message);
        if (!$index || $index % 16) {
            throw new InvalidPaddingException('Invalid message length');
        }

        $limit = 16;
        while ($limit-- && $message[--$index] === "\0");

        if ($message[$index] !== "\x80") {
            throw new InvalidPaddingException('Invalid padding');
        }

        return 16 - $limit;
    }
} 

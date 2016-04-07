<?php declare(strict_types = 1);

namespace AES\Padding;

use AES\Exception\InvalidPaddingException;

class ANSIX923 implements Scheme
{
    function getPadding(string $message): string
    {
        $padLen = 16 - (strlen($message) % 16);
        return str_repeat("\0", $padLen - 1) . chr($padLen);
    }

    function getPaddingLength(string $message): int
    {
        $messageLen = strlen($message);
        if (!$messageLen || $messageLen % 16) {
            throw new InvalidPaddingException('Invalid message length');
        }

        $padLen = ord($message[$messageLen - 1]);
        if (!$padLen || $padLen > 16) {
            throw new InvalidPaddingException('Invalid padding');
        }

        $i = $messageLen - 1;
        $limit = $messageLen - $padLen;
        while ($i > $limit) {
            if ($message[--$i] !== "\0") {
                throw new InvalidPaddingException('Invalid padding');
            }
        }

        return $padLen;
    }
} 

<?php declare(strict_types = 1);

namespace AES\Padding;

use AES\Exception\InvalidPaddingException;

class PKCS7 implements Scheme
{
    function getPadding(string $message): string
    {
        $padLen = 16 - (strlen($message) % 16);
        return str_repeat(chr($padLen), $padLen);
    }

    function getPaddingLength(string $message): int
    {
        $messageLen = strlen($message);
        if (!$messageLen || $messageLen % 16) {
            throw new InvalidPaddingException('Invalid message length');
        }
 
        $padChar = $message[$messageLen - 1];
        $padLen = ord($padChar);
        if (!$padLen || $padLen > 16) {
            throw new InvalidPaddingException('Invalid padding');
        }

        $i = $messageLen - 1;
        $limit = $messageLen - $padLen;
        while ($i > $limit) {
            if ($message[--$i] !== $padChar) {
                throw new InvalidPaddingException('Invalid padding');
            }
        }

        return $padLen;
    }
} 

<?php

namespace AES\Padding;

class PKCS7 implements Scheme
{
    function getPadding($message)
    {
        $padLen = (16 - (strlen($message) % 16)) ?: 16;
        return str_repeat(chr($padLen), $padLen);
    }

    function getPadLen($message)
    {
        $index = strlen($message);
        if (!$index || $index % 16) {
            throw new \Exception('Invalid message');
        }

        $padChar = $message[$index - 1];
        $padLen = ord($padChar);
        $limit = $index - $padLen;
        if (!$padLen || $limit < 0) {
            throw new \Exception('Invalid padding');
        }

        for ($i = $index - 2; $i > $limit; $i--) {
            if ($message[$i] !== $padChar) {
                throw new \Exception('Invalid padding');
            }
        }
        return $padLen;
    }
} 

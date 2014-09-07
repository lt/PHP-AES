<?php

namespace AES\Padding;

class ANSIX923 implements Scheme
{
    function getPadding($message)
    {
        $padLen = (16 - (strlen($message) % 16)) ?: 16;
        return str_repeat("\0", $padLen - 1) . chr($padLen);
    }

    function getPadLen($message)
    {
        $index = strlen($message);
        if (!$index || $index % 16) {
            throw new \Exception('Invalid message');
        }

        $padLen = ord($message[$index - 1]);
        $limit = $index - $padLen;
        if (!$padLen || $limit < 0) {
            throw new \Exception('Invalid padding');
        }

        $i = $index - 2;
        while ($i >= $limit) {
            if ($message[$i--] !== "\0") {
                throw new \Exception('Invalid padding');
            }
        }

        return $padLen;
    }
} 

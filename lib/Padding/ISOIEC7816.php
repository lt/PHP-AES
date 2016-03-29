<?php

namespace AES\Padding;

class ISOIEC7816 implements Scheme
{
    function getPadding($message)
    {
        $padLen = (16 - (strlen($message) % 16)) ?: 16;
        return "\x80" . str_repeat("\0", $padLen - 1);
    }

    function getPadLen($message)
    {
        $index = strlen($message);
        if (!$index || $index % 16) {
            throw new \Exception('Invalid message');
        }

        $limit = 16;
        while ($limit-- && $message[--$index] === "\0");

        if ($message[$index] !== "\x80") {
            throw new \Exception('Invalid padding');
        }

        return 16 - $limit;
    }
} 

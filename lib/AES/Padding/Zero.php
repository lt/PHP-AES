<?php

namespace AES\Padding;

class Zero implements Scheme
{
    function getPadding($message)
    {
        $remainder = strlen($message) % 16;
        return $remainder ? str_repeat("\0", 16 - $remainder) : '';
    }

    function getPadLen($message)
    {
        return 0;
    }
} 

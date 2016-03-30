<?php

namespace AES\Context;

use AES\Cipher;

class ECB
{
    public $key;
    public $keyLen;

    function __construct($key)
    {
        $this->key = Cipher::generateKey($key);
    }
} 

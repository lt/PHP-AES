<?php

namespace AES\Context;

use AES\Cipher;

class CBC
{
    public $key;
    public $keyLen;

    public $IV;

    function __construct($key, $iv)
    {
        $this->key = Cipher::generateKey($key);
        $this->IV = array_values(unpack('N4', $iv));
    }
} 

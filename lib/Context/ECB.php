<?php

namespace AES\Context;

use AES\Cipher;

class ECB
{
    public $RK;
    public $RKi;
    public $keyLen;

    function __construct($key)
    {
        list($this->RK, $this->RKi, $this->keyLen) = Cipher::generateKey($key);
    }
} 

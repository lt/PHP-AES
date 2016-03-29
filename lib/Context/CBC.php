<?php

namespace AES\Context;

use AES\Cipher;

class CBC
{
    public $RK;
    public $RKi;
    public $keyLen;

    public $IV;

    function __construct($key, $iv)
    {
        list($this->RK, $this->RKi, $this->keyLen) = Cipher::generateKey($key);
        $this->IV = array_values(unpack('N4', $iv));
    }
} 

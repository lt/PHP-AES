<?php

namespace AES\Context;

use AES\Cipher;

class CTR
{
    public $key;
    public $keyLen;

    public $nonce;
    public $buffer = '';

    function __construct($key, $nonce)
    {
        $this->key = Cipher::generateKey($key);
        $this->nonce = array_values(unpack('N4', $nonce));
    }
}

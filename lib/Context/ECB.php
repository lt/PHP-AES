<?php declare(strict_types = 1);

namespace AES\Context;

use AES\Key;

class ECB
{
    public $key;
    public $keyLen;

    function __construct(string $key)
    {
        $this->key = new Key($key);
    }
} 

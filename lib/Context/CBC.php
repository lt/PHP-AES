<?php declare(strict_types = 1);

namespace AES\Context;

use AES\Key;

class CBC
{
    public $key;
    public $keyLen;

    public $IV;

    function __construct(string $key, string $iv)
    {
        $this->key = new Key($key);
        $this->IV = $iv;
    }
} 

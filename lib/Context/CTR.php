<?php declare(strict_types = 1);

namespace AES\Context;

use AES\Key;

class CTR
{
    public $key;
    public $keyLen;

    public $nonce;
    public $buffer = '';

    function __construct(string $key, string $nonce)
    {
        $this->key = new Key($key);
        $this->nonce = array_values(unpack('N4', $nonce));
    }
}

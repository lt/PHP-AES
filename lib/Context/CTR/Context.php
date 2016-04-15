<?php declare(strict_types = 1);

namespace AES\Context\CTR;

abstract class Context
{
    public $key;
    public $nonce;
    public $keyStream = '';
}

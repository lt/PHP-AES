<?php declare(strict_types = 1);

namespace AES\Context\OFB;

abstract class Context
{
    public $key;
    public $iv;
    public $keyStream = '';
}

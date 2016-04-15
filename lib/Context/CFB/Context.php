<?php declare(strict_types = 1);

namespace AES\Context\CFB;

abstract class Context
{
    public $key;
    public $iv;
    public $keyStream = '';
}

<?php declare(strict_types = 1);

namespace AES;

abstract class Context
{
    const MODE_ENCRYPT = 1;
    const MODE_DECRYPT = 2;

    public $mode = 0;
}

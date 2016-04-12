<?php declare(strict_types = 1);

namespace AES\Context;

use AES\Context;

class OCB extends Context
{
    public $key;

    public $lstar;
    public $ldollar;

    public $sum;
    public $offset;
    public $blockIndex;

    public $mode;
    public $finalised = false;
}

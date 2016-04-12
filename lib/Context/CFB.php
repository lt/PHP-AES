<?php declare(strict_types = 1);

namespace AES\Context;

use AES\Context;

class CFB extends Context
{
    public $key;
    public $state;
    public $buffer = '';
}

<?php declare(strict_types = 1);

namespace AES\Context;

use AES\Context;

class CTR extends Context
{
    public $key;
    public $state;
    public $buffer = '';
}

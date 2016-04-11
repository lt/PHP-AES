<?php declare(strict_types = 1);

namespace AES\Context;

class CTR
{
    public $key;
    public $state;
    public $buffer = '';
}

<?php declare(strict_types = 1);

namespace AES\Context;

class OFB
{
    public $key;
    public $state;
    public $buffer = '';
}

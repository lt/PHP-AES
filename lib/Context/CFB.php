<?php declare(strict_types = 1);

namespace AES\Context;

class CFB
{
    public $key;
    public $state;
    public $buffer = '';
}

<?php declare(strict_types = 1);

namespace AES\Context;

class OCB
{
    public $key;

    public $lstar;
    public $ldollar;

    public $sum;
    public $offset;

    public $buffer = '';
}

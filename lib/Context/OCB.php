<?php declare(strict_types = 1);

namespace AES\Context;

use AES\Context;

class OCB extends Context
{
    public $key;

    public $lstar;
    public $ldollar;

    public $messageSum = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    public $messageOffset; // Calculated during init
    public $messageBlock = 0;
    public $messageBuffer = '';
    
    public $aadSum = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    public $aadOffset = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    public $aadBlock = 0;
    public $aadBuffer = '';

    public $mode;
    public $finalised = false;
}

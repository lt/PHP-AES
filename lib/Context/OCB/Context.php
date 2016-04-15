<?php declare(strict_types = 1);

namespace AES\Context\OCB;

abstract class Context
{
    public $key;

    public $lstar;
    public $ldollar;

    public $cryptSum = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    public $cryptOffset; // Calculated during init
    public $cryptIndex = 0;
    public $cryptBuffer = '';
    
    public $aadSum = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    public $aadOffset = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    public $aadBlock = 0;
    public $aadBuffer = '';

    public $mode;
    public $finalised = false;
}

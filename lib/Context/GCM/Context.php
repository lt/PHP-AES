<?php declare(strict_types = 1);

namespace AES\Context\GCM;

abstract class Context
{
    public $key;
    public $nonce;
    
    public $table;
    public $H_lo;
    public $H_hi;
    
    public $T;
    public $tag = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    public $aadLen = 0;
    public $aadBuffer = '';
    
    public $messageLen = 0;
    public $messageBuffer = '';
        
    public $blockIndex = 1;
}

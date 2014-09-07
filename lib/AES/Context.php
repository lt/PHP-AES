<?php

namespace AES;

class Context
{
    // Set by block cipher
    public $RK;
    public $RKi;
    public $keyLength;
    public $blockCipher;

    // Set by stream mode
    public $iv;
    public $padding;
    public $buffer;
    public $streamMode;
}

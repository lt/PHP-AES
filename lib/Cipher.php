<?php

namespace AES;

abstract class Cipher
{
    static function generateKey($key)
    {
        return new Key($key);
    }
}

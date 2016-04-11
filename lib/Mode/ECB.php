<?php declare(strict_types = 1);

namespace AES\Mode;

use AES\Cipher;
use AES\Key;

class ECB extends Cipher
{
    function encrypt(Key $key, string $message): string
    {
        $offset = 0;
        $out = '';
        
        $blocks = strlen($message) >> 4;
        while ($blocks--) {
            $out .= $this->encryptBlock($key, substr($message, $offset, 16));
            $offset += 16;
        }

        return $out;
    }

    function decrypt(Key $key, string $message): string
    {
        $offset = 0;
        $out = '';

        $blocks = strlen($message) >> 4;
        while ($blocks--) {
            $out .= $this->decryptBlock($key, substr($message, $offset, 16));
            $offset += 16;
        }

        return $out;
    }
} 

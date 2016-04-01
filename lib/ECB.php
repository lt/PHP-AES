<?php declare(strict_types = 1);

namespace AES;

class ECB extends Cipher
{
    private $key;

    function __construct(Key $key)
    {
        $this->key = $key;
    }
    
    function encrypt(string $message): string
    {
        $offset = 0;
        $out = '';
        
        $blocks = strlen($message) >> 4;
        while ($blocks--) {
            $out .= $this->encryptBlock($this->key, substr($message, $offset, 16));
            $offset += 16;
        }

        return $out;
    }

    function decrypt(string $message): string
    {
        $offset = 0;
        $out = '';

        $blocks = strlen($message) >> 4;
        while ($blocks--) {
            $out .= $this->decryptBlock($this->key, substr($message, $offset, 16));
            $offset += 16;
        }

        return $out;
    }
} 

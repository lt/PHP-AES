<?php declare(strict_types = 1);

namespace AES;

class CBC extends Cipher
{
    private $key;
    private $iv;

    function __construct(Key $key, string $iv)
    {
        if (strlen($iv) !== 16) {
            throw new IVLengthException;
        }

        $this->key = $key;
        $this->iv = $iv;
    }
    
    function encrypt(string $message): string
    {
        $offset = 0;
        $out = '';
        $iv = $this->iv;

        $blocks = strlen($message) >> 4;
        while ($blocks--) {
            $out .= $iv = $this->encryptBlock($this->key, substr($message, $offset, 16) ^ $iv);
            $offset += 16;
        }

        $this->iv = $iv;

        return $out;
    }

    function decrypt(string $message): string
    {
        $offset = 0;
        $out = '';
        $iv = $this->iv;

        $blocks = strlen($message) >> 4;
        while ($blocks--) {
            $out .= $this->decryptBlock($this->key, $block = substr($message, $offset, 16)) ^ $iv;
            $iv = $block;
            $offset += 16;
        }

        $this->iv = $iv;

        return $out;
    }
}

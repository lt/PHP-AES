<?php declare(strict_types = 1);

namespace AES;

class OFB extends Cipher
{
    private $key;
    private $iv;
    private $buffer = '';

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
        $iv = $this->iv;
        $keyStream = $this->buffer;

        $bytesRequired = strlen($message) - strlen($keyStream);
        $bytesOver = $bytesRequired % 16;

        $blocks = ($bytesRequired >> 4) + ($bytesOver > 0);
        while ($blocks--) {
            $keyStream .= $iv = $this->encryptBlock($this->key, $iv);
        }

        $this->buffer = substr($keyStream, $bytesRequired);
        $this->iv = $iv;

        return $message ^ $keyStream;
    }

    function decrypt(string $message): string
    {
        return $this->encrypt($message);
    }
} 

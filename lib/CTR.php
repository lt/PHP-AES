<?php declare(strict_types = 1);

namespace AES;

use AES\Exception\IVLengthException;

class CTR extends Cipher
{
    private $key;
    private $nonce;
    private $buffer = '';

    function __construct(Key $key, string $nonce)
    {
        if (strlen($nonce) !== 16) {
            throw new IVLengthException;
        }
        
        $this->key = $key;
        $this->nonce = array_values(unpack('N4', $nonce));
    }
    
    function encrypt(string $message): string
    {
        $nonce = $this->nonce;
        $keyStream = $this->buffer;

        $bytesRequired = strlen($message) - strlen($keyStream);
        $bytesOver = $bytesRequired % 16;

        $blocks = ($bytesRequired >> 4) + ($bytesOver > 0);
        while ($blocks--) {
            $keyStream .= $this->encryptBlock($this->key, pack('N4', ...$nonce));

            for($i = 3; $i >= 0; $i--) {
                $nonce[$i]++;
                $nonce[$i] &= 0xffffffff;
                if ($nonce[$i]) {
                    break;
                }
            }
        }

        $this->buffer = substr($keyStream, $bytesRequired);
        $this->nonce = $nonce;

        return $message ^ $keyStream;
    }

    function decrypt(string $message): string
    {
        return $this->encrypt($message);
    }
} 

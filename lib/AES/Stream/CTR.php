<?php

namespace AES\Stream;

use AES\Block\Cipher;

class CTR extends Mode
{
    function encrypt(Cipher $cipher, $plaintext, $nonce)
    {
        if (!is_string($nonce) || strlen($nonce) !== 16) {
            throw new \InvalidArgumentException('Nonce length must be a multiple of 16 bytes');
        }

        $out = '';
        $offset = 0;
        $messageLen = strlen($plaintext);
        while ($offset < $messageLen) {
            $out .= $cipher->encrypt($nonce) ^ substr($plaintext, $offset, 16);
            for($i = 15; $i >= 0; $i--) {
                if (($nonce[$i] = chr((ord($nonce[$i]) + 1) & 0xff)) !== "\0") {
                    break;
                }
            }
            $offset += 16;
        }

        return $out;
    }

    function decrypt(Cipher $cipher, $ciphertext, $nonce)
    {
        return $this->encrypt($cipher, $ciphertext, $nonce);
    }
} 

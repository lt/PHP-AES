<?php declare(strict_types = 1);

namespace AES;

class ECB extends Cipher
{
    function encrypt(Key $key, string $message): string
    {
        $ciphertext = '';

        $messageOffset = 0;
        $blockCount = strlen($message) >> 4;
        while ($blockCount--) {
            $messageBlock = substr($message, $messageOffset, 16);
            $ciphertext .= $this->encryptBlock($key, $messageBlock);

            $messageOffset += 16;
        }

        return $ciphertext;
    }

    function decrypt(Key $key, string $message): string
    {
        $plaintext = '';

        $messageOffset = 0;
        $blockCount = strlen($message) >> 4;
        while ($blockCount--) {
            $messageBlock = substr($message, $messageOffset, 16);
            $plaintext .= $this->decryptBlock($key, $messageBlock);

            $messageOffset += 16;
        }

        return $plaintext;
    }
} 

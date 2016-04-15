<?php declare(strict_types = 1);

namespace AES;

use AES\Context\CBC\{
    Context,
    EncryptionContext,
    DecryptionContext
};
use AES\Exception\IVLengthException;

class CBC extends Cipher
{
    private function init(Context $context, Key $key, string $iv)
    {
        if (strlen($iv) !== 16) {
            throw new IVLengthException;
        }

        $context->key = $key;
        $context->iv = $iv;
    }

    function initEncryption(Key $key, string $iv): EncryptionContext
    {
        $context = new EncryptionContext;
        $this->init($context, $key, $iv);
        return $context;
    }

    function initDecryption(Key $key, string $iv): DecryptionContext
    {
        $context = new DecryptionContext;
        $this->init($context, $key, $iv);
        return $context;
    }

    function encrypt(EncryptionContext $context, string $message): string
    {
        $ciphertext = '';

        $iv = $context->iv;
        
        $messageOffset = 0;
        $blockCount = strlen($message) >> 4;
        while ($blockCount--) {
            $messageBlock = substr($message, $messageOffset, 16);
            $encryptedBlock = $this->encryptBlock($context->key, $messageBlock ^ $iv);
            $ciphertext .= $encryptedBlock;
            $iv = $encryptedBlock;
            
            $messageOffset += 16;
        }

        $context->iv = $iv;

        return $ciphertext;
    }

    function decrypt(DecryptionContext $context, string $message): string
    {
        $plaintext = '';

        $iv = $context->iv;
        
        $messageOffset = 0;
        $blockCount = strlen($message) >> 4;
        while ($blockCount--) {
            $messageBlock = substr($message, $messageOffset, 16);
            $decryptedBlock = $this->decryptBlock($context->key, $messageBlock) ^ $iv;
            $plaintext .= $decryptedBlock;
            $iv = $messageBlock;
            
            $messageOffset += 16;
        }

        $context->iv = $iv;

        return $plaintext;
    }
}

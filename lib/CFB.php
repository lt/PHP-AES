<?php declare(strict_types = 1);

namespace AES;

use AES\Context\CFB\{
    Context,
    EncryptionContext,
    DecryptionContext
};
use AES\Exception\IVLengthException;

class CFB extends Cipher
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
    
    function streamEncrypt(EncryptionContext $context, string $message): string
    {
        $keyStream = $context->keyStream;

        // Since this is a stream mode the output doesn't have to be aligned to block boundaries.
        // However we only get a new IV when a block (i.e. keyStream) has been fully consumed.

        // It's possible that it may take several calls (i.e. short messages) to consume the block,
        // so the IV is built up as we go.

        // The len(iv) + len(keyStream) should always be equal to 16
        $ciphertext = $message ^ $keyStream;
        $iv = $context->iv . $ciphertext;

        // if the message was short and didn't consume the remaining
        // keyStream then 0 bytes are required and the loop is skipped
        $messageOffset = strlen($ciphertext);
        $bytesRequired = strlen($message) - $messageOffset;
        $bytesOver = $bytesRequired % 16;

        $blockCount = ($bytesRequired >> 4) + ($bytesOver > 0);
        while ($blockCount--) {
            $messageBlock = substr($message, $messageOffset, 16);
            $keyStream = $this->encryptBlock($context->key, $iv);

            // len(iv) can be less than 16 on the last block
            $encryptedBlock = $keyStream ^ $messageBlock;
            $iv = $encryptedBlock;
            $ciphertext .= $encryptedBlock;
            
            $messageOffset += 16;
        }

        $context->keyStream = substr($keyStream, strlen($iv));
        $context->iv = $iv;

        return $ciphertext;
    }

    function streamDecrypt(DecryptionContext $context, string $message): string
    {
        $keyStream = $context->keyStream;

        // Similar to encrypt, we only get a new iv for each block-aligned
        // piece of ciphertext, so we need to build it as we go in case of
        // many calls with small messages
        $plaintext = $message ^ $keyStream;
        $messageOffset = strlen($plaintext);
        $iv = $context->iv . substr($message, 0, $messageOffset);

        $bytesRequired = strlen($message) - $messageOffset;
        $bytesOver = $bytesRequired % 16;

        $blockCount = ($bytesRequired >> 4) + ($bytesOver > 0);
        while ($blockCount--) {
            $messageBlock = substr($message, $messageOffset, 16);
            $keyStream = $this->encryptBlock($context->key, $iv);

            $decryptedBlock = $keyStream ^ $messageBlock;
            $iv = $messageBlock;
            $plaintext .= $decryptedBlock;

            $messageOffset += 16;
        }

        $context->keyStream = substr($keyStream, strlen($iv));
        $context->iv = $iv;

        return $plaintext;
    }
    
    function encrypt(Key $key, string $iv, string $message): string
    {
        $context = $this->initEncryption($key, $iv);
        return $this->streamEncrypt($context, $message);
    }

    function decrypt(Key $key, string $iv, string $message): string
    {
        $context = $this->initDecryption($key, $iv);
        return $this->streamDecrypt($context, $message);
    }
} 

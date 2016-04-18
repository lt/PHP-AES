<?php declare(strict_types = 1);

namespace AES;

use AES\Context\CTR\{
    Context,
    EncryptionContext,
    DecryptionContext
};
use AES\Exception\IVLengthException;

class CTR extends Cipher
{
    private function init(Context $context, Key $key, string $nonce)
    {
        if (strlen($nonce) !== 16) {
            throw new IVLengthException;
        }

        $context->key = $key;
        $context->nonce = array_values(unpack('N4', $nonce));
    }

    function initEncryption(Key $key, string $nonce): EncryptionContext
    {
        $context = new EncryptionContext;
        $this->init($context, $key, $nonce);
        return $context;
    }

    function initDecryption(Key $key, string $nonce): DecryptionContext
    {
        $context = new DecryptionContext;
        $this->init($context, $key, $nonce);
        return $context;
    }
    
    private function transcrypt(Context $context, string $message): string
    {
        $nonce = $context->nonce;
        $keyStream = $context->keyStream;

        $bytesRequired = strlen($message) - strlen($keyStream);
        $bytesOver = $bytesRequired % 16;

        $blockCount = ($bytesRequired >> 4) + ($bytesOver > 0);
        while ($blockCount--) {
            $keyStream .= $this->encryptBlock($context->key, pack('N4', ...$nonce));

            for($i = 3; $i >= 0; $i--) {
                $nonce[$i]++;
                $nonce[$i] &= 0xffffffff;
                if ($nonce[$i]) {
                    break;
                }
            }
        }

        $context->keyStream = substr($keyStream, $bytesRequired);
        $context->nonce = $nonce;

        return $message ^ $keyStream;
    }
    
    function streamEncrypt(EncryptionContext $ctx, string $message): string
    {
        return $this->transcrypt($ctx, $message);
    }

    function streamDecrypt(DecryptionContext $ctx, string $message): string
    {
        return $this->transcrypt($ctx, $message);
    }

    function encrypt(Key $key, string $nonce, string $message): string
    {
        $context = $this->initEncryption($key, $nonce);
        return $this->streamEncrypt($context, $message);
    }

    function decrypt(Key $key, string $nonce, string $message): string
    {
        $context = $this->initDecryption($key, $nonce);
        return $this->streamDecrypt($context, $message);
    }
} 

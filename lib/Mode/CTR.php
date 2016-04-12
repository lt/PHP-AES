<?php declare(strict_types = 1);

namespace AES\Mode;

use AES\Cipher;
use AES\Context\CTR as Context;
use AES\Exception\InvalidContextException;
use AES\Exception\IVLengthException;
use AES\Key;

class CTR extends Cipher
{
    function init(Key $key, string $nonce): Context
    {
        if (strlen($nonce) !== 16) {
            throw new IVLengthException;
        }

        $ctx = new Context;

        $ctx->key = $key;
        $ctx->state = array_values(unpack('N4', $nonce));

        return $ctx;
    }
    
    private function transcrypt(Context $ctx, string $message): string
    {
        $nonce = $ctx->state;
        $keyStream = $ctx->buffer;

        $bytesRequired = strlen($message) - strlen($keyStream);
        $bytesOver = $bytesRequired % 16;

        $blocks = ($bytesRequired >> 4) + ($bytesOver > 0);
        while ($blocks--) {
            $keyStream .= $this->encryptBlock($ctx->key, pack('N4', ...$nonce));

            for($i = 3; $i >= 0; $i--) {
                $nonce[$i]++;
                $nonce[$i] &= 0xffffffff;
                if ($nonce[$i]) {
                    break;
                }
            }
        }

        $ctx->buffer = substr($keyStream, $bytesRequired);
        $ctx->state = $nonce;

        return $message ^ $keyStream;
    }
    
    function encrypt(Context $ctx, string $message): string
    {
        if ($ctx->mode === Context::MODE_DECRYPT) {
            throw new InvalidContextException('Decryption context supplied to encryption method');
        }
        $ctx->mode = Context::MODE_ENCRYPT;

        return $this->transcrypt($ctx, $message);
    }

    function decrypt(Context $ctx, string $message): string
    {
        if ($ctx->mode === Context::MODE_ENCRYPT) {
            throw new InvalidContextException('Encryption context supplied to decryption method');
        }
        $ctx->mode = Context::MODE_DECRYPT;

        return $this->transcrypt($ctx, $message);
    }
} 

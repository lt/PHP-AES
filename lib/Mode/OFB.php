<?php declare(strict_types = 1);

namespace AES\Mode;

use AES\Cipher;
use AES\Context\OFB as Context;
use AES\Exception\InvalidContextException;
use AES\Exception\IVLengthException;
use AES\Key;

class OFB extends Cipher
{
    function init(Key $key, string $iv): Context
    {
        if (strlen($iv) !== 16) {
            throw new IVLengthException;
        }

        $ctx = new Context;

        $ctx->key = $key;
        $ctx->state = $iv;

        return $ctx;
    }

    function transcrypt(Context $ctx, string $message): string
    {
        $iv = $ctx->state;
        $keyStream = $ctx->buffer;

        $bytesRequired = strlen($message) - strlen($keyStream);
        $bytesOver = $bytesRequired % 16;

        $blocks = ($bytesRequired >> 4) + ($bytesOver > 0);
        while ($blocks--) {
            $keyStream .= $iv = $this->encryptBlock($ctx->key, $iv);
        }

        $ctx->buffer = substr($keyStream, $bytesRequired);
        $ctx->state = $iv;

        return $message ^ $keyStream;
    }

    function encrypt(Context $ctx, string $message): string
    {
        if ($ctx->mode === Context::MODE_DECRYPT) {
            throw new InvalidContextException('Decryption context supplied to encryption method');
        }
        $ctx->mode = Context::MODE_ENCRYPT;

        return $this->encrypt($ctx, $message);
    }

    function decrypt(Context $ctx, string $message): string
    {
        if ($ctx->mode === Context::MODE_ENCRYPT) {
            throw new InvalidContextException('Encryption context supplied to decryption method');
        }
        $ctx->mode = Context::MODE_DECRYPT;

        return $this->encrypt($ctx, $message);
    }
} 

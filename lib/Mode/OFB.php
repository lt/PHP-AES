<?php declare(strict_types = 1);

namespace AES\Mode;

use AES\Cipher;
use AES\Context\OFB as Context;
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

    function encrypt(Context $ctx, string $message): string
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

    // Unnecessary but signals intent
    function decrypt(Context $ctx, string $message): string
    {
        return $this->encrypt($ctx, $message);
    }
} 

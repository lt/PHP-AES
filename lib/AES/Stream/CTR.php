<?php

namespace AES\Stream;

use AES\Context;
use AES\Block\Cipher;

class CTR implements Mode
{
    function init(Context $ctx, Cipher $cipher, $key, $nonce)
    {
        $cipher->init($ctx, $key);

        $ctx->iv = $nonce;
        $ctx->buffer = '';
        $ctx->streamMode = $this;
    }

    function encrypt(Context $ctx, $message, $final = false)
    {
        if (!($ctx->streamMode instanceof $this)) {
            throw new \InvalidArgumentException('Context not initialised for this stream mode');
        }

        if ($ctx->buffer) {
            $message = $ctx->buffer . $message;
            $ctx->buffer = '';
        }

        $out = '';
        $offset = 0;
        $nonce = $ctx->iv;
        $cipher = $ctx->blockCipher;
        $messageLen = strlen($message);
        $blocks = ($messageLen >> 4) + ($final && ($messageLen % 16));

        while ($blocks--) {
            $out .= $cipher->encryptBlock($ctx, $nonce) ^ substr($message, $offset, 16);
            for($i = 15; $i >= 0; $i--) {
                if (($nonce[$i] = chr((ord($nonce[$i]) + 1) & 0xff)) !== "\0") {
                    break;
                }
            }
            $offset += 16;
        }

        if ($offset < $messageLen) {
            $ctx->buffer = substr($message, $offset);
        }

        if ($final) {
            $ctx = new Context();
        }
        else {
            $ctx->iv = $nonce;
        }

        return $out;
    }

    function decrypt(Context $ctx, $message, $final = false)
    {
        return $this->encrypt($ctx, $message, $final);
    }
} 

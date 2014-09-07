<?php

namespace AES\Stream;

use AES\Context;
use AES\Block\Cipher;
use AES\Padding\Scheme;
use AES\Padding\Zero;

class CBC implements Mode
{
    function init(Context $ctx, Cipher $cipher, $key, $iv, Scheme $padding = null)
    {
        $cipher->init($ctx, $key);

        if (is_null($padding)) {
            $padding = new Zero();
        }

        $ctx->iv = $iv;
        $ctx->padding = $padding;
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

        if ($final) {
            $message .= $ctx->padding->getPadding($message);
        }

        $out = '';
        $offset = 0;
        $iv = $ctx->iv;
        $cipher = $ctx->blockCipher;
        $messageLen = strlen($message);
        $blocks = $messageLen >> 4;

        while ($blocks--) {
            $out .= $iv = $cipher->encryptBlock($ctx, substr($message, $offset, 16) ^ $iv);
            $offset += 16;
        }

        if ($offset < $messageLen) {
            $ctx->buffer = substr($message, $offset);
        }

        if ($final) {
            $ctx = new Context();
        }
        else {
            $ctx->iv = $iv;
        }

        return $out;
    }

    function decrypt(Context $ctx, $message, $final = false)
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
        $iv = $ctx->iv;
        $cipher = $ctx->blockCipher;
        $messageLen = strlen($message);
        $blocks = $messageLen >> 4;

        while ($blocks--) {
            $out .= $cipher->decryptBlock($ctx, $block = substr($message, $offset, 16)) ^ $iv;
            $iv = $block;
            $offset += 16;
        }

        if ($offset < $messageLen) {
            $ctx->buffer = substr($message, $offset);
        }

        if ($final) {
            $padLen = $ctx->padding->getPadLen($message);
            if ($padLen) {
                $out = substr($out, -$padLen);
            }
            $ctx = new Context();
        }
        else {
            $ctx->iv = $iv;
        }

        return $out;
    }
} 

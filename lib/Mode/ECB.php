<?php declare(strict_types = 1);

namespace AES\Mode;

use AES\Cipher;
use AES\Context\ECB as Context;

class ECB extends Cipher
{
    function encrypt(Context $ctx, string $message): string
    {
        $offset = 0;
        $out = '';
        
        $blocks = strlen($message) >> 4;
        while ($blocks--) {
            $out .= $this->encryptBlock($ctx->key, substr($message, $offset, 16));
            $offset += 16;
        }

        return $out;
    }

    function decrypt(Context $ctx, string $message): string
    {
        $offset = 0;
        $out = '';

        $blocks = strlen($message) >> 4;
        while ($blocks--) {
            $out .= $this->decryptBlock($ctx->key, substr($message, $offset, 16));
            $offset += 16;
        }

        return $out;
    }
} 

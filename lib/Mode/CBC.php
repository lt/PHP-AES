<?php declare(strict_types = 1);

namespace AES\Mode;

use AES\Cipher;
use AES\Context\CBC as Context;

class CBC extends Cipher
{
    function encrypt(Context $ctx, string $message): string
    {
        $offset = 0;
        $out = '';
        $iv = $ctx->IV;

        $blocks = strlen($message) >> 4;
        while ($blocks--) {
            $out .= $iv = $this->encryptBlock($ctx->key, substr($message, $offset, 16) ^ $iv);
            $offset += 16;
        }

        $ctx->IV = $iv;

        return $out;
    }

    function decrypt(Context $ctx, string $message): string
    {
        $offset = 0;
        $out = '';
        $iv = $ctx->IV;

        $blocks = strlen($message) >> 4;
        while ($blocks--) {
            $out .= $this->decryptBlock($ctx->key, $block = substr($message, $offset, 16)) ^ $iv;
            $iv = $block;
            $offset += 16;
        }

        $ctx->IV = $iv;

        return $out;
    }
}

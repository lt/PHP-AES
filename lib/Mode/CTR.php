<?php declare(strict_types = 1);

namespace AES\Mode;

use AES\Cipher;
use AES\Context\CTR as Context;

class CTR extends Cipher
{
    function encrypt(Context $ctx, string $message): string
    {
        $nonce = $ctx->nonce;
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
        $ctx->nonce = $nonce;

        return $message ^ $keyStream;
    }

    function decrypt(Context $ctx, string $message): string
    {
        return $this->encrypt($ctx, $message);
    }
} 

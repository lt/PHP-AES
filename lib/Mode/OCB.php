<?php declare(strict_types = 1);

namespace AES\Mode;

use AES\Cipher;
use AES\Context\OCB as Context;
use AES\Exception\AuthenticationException;
use AES\Exception\InvalidContextException;
use AES\Exception\IVLengthException;
use AES\Key;

class OCB extends Cipher
{
    const NONCEBYTES = 12;
    const TAGBYES = 16;

    function init(Key $key, string $nonce): Context
    {
        if (strlen($nonce) !== self::NONCEBYTES) {
            throw new IVLengthException;
        }

        $ctx =  new Context;

        $ctx->key = $key;
        $ctx->lstar = $this->encryptBlock($key, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
        $ctx->ldollar = $this->calc_L_i($ctx->lstar, 1);

        $nonce = str_pad($nonce, 16, "\0", STR_PAD_LEFT);
        $nonce[0] = chr(((self::TAGBYES << 3) % 128) << 1);
        $nonceOffset = 16 - self::NONCEBYTES - 1;
        $nonce[$nonceOffset] = $nonce[$nonceOffset] | "\1";
        $bottom = ord($nonce[15]) & 0x3f;
        $nonce[15] = $nonce[15] & "\xc0";

        $ktop = $this->encryptBlock($ctx->key, $nonce);
        list(, $stretch0, $stretch1, $stretch2) = unpack('J3', $ktop . (substr($ktop, 1, 8) ^ $ktop));

        $bottomMask = ~(-1 << $bottom);
        $messageOffset = pack('J2',
            $stretch0 << $bottom | (($stretch1 >> (64 - $bottom)) & $bottomMask),
            $stretch1 << $bottom | (($stretch2 >> (64 - $bottom)) & $bottomMask)
        );

        $ctx->messageOffset = $messageOffset;

        return $ctx;
    }

    private function calc_L_i(string $ldollar, int $i): string
    {
        list(, $l0, $l1) = unpack('J2', $ldollar);

        do {
            $tmp = ($l0 >> 63 & 1);
            $l0 = $l0 << 1 | ($l1 >> 63 & 1);
            $l1 = $l1 << 1 ^ ($tmp * 135);
        } while (($i & 1) === 0 && $i >>= 1);

        return pack('J2', $l0, $l1);
    }

    function aad(Context $ctx, string $aad)
    {
        if ($ctx->finalised) {
            throw new InvalidContextException('Cannot process more data after finalise() has been called.');
        }

        $aad = $ctx->aadBuffer . $aad;

        $aadOffset = $ctx->aadOffset;
        $aadSum = $ctx->aadSum;
        $blockIndex = $ctx->aadBlock;

        $blockOffset = 0;
        $blocks = strlen($aad) >> 4;
        while ($blocks--) {
            $block = substr($aad, $blockOffset, 16);
            $aadOffset ^= $this->calc_L_i($ctx->ldollar, ++$blockIndex);

            $aadSum ^= $this->encryptBlock($ctx->key, $aadOffset ^ $block);

            $blockOffset += 16;
        }

        $ctx->aadOffset = $aadOffset;
        $ctx->aadSum = $aadSum;
        $ctx->aadBlock = $blockIndex;
        $ctx->aadBuffer = substr($aad, $blockOffset);
    }

    function encrypt(Context $ctx, string $message): string
    {
        if ($ctx->finalised) {
            throw new InvalidContextException('Cannot process more data after finalise() has been called.');
        }

        if ($ctx->mode === Context::MODE_DECRYPT) {
            throw new InvalidContextException('Decryption context supplied to encryption method');
        }
        $ctx->mode = Context::MODE_ENCRYPT;

        $message = $ctx->messageBuffer . $message;

        $messageOffset = $ctx->messageOffset;
        $messageSum = $ctx->messageSum;
        $blockIndex = $ctx->messageBlock;

        $ciphertext = '';
        $blockOffset = 0;
        $blocks = strlen($message) >> 4;
        while ($blocks--) {
            $block = substr($message, $blockOffset, 16);
            $messageOffset ^= $this->calc_L_i($ctx->ldollar, ++$blockIndex);

            $messageSum ^= $block;
            $ciphertext .= $messageOffset ^ $this->encryptBlock($ctx->key, $messageOffset ^ $block);

            $blockOffset += 16;
        }

        $ctx->messageOffset = $messageOffset;
        $ctx->messageSum = $messageSum;
        $ctx->messageBlock = $blockIndex;
        $ctx->messageBuffer = substr($message, $blockOffset);

        return $ciphertext;
    }

    function decrypt(Context $ctx, string $message): string
    {
        if ($ctx->finalised) {
            throw new InvalidContextException('Cannot process more data after finalise() has been called.');
        }

        if ($ctx->mode === Context::MODE_ENCRYPT) {
            throw new InvalidContextException('Encryption context supplied to decryption method');
        }
        $ctx->mode = Context::MODE_DECRYPT;

        $message = $ctx->messageBuffer . $message;
        $messageOffset = $ctx->messageOffset;
        $messageSum = $ctx->messageSum;
        $blockIndex = $ctx->messageBlock;

        $plaintext = '';
        $blockOffset = 0;
        $blocks = strlen($message) >> 4;
        while ($blocks--) {
            $block = substr($message, $blockOffset, 16);
            $messageOffset ^= $this->calc_L_i($ctx->ldollar, ++$blockIndex);

            $plain = $messageOffset ^ $this->decryptBlock($ctx->key, $messageOffset ^ $block);
            $messageSum ^= $plain;
            $plaintext .= $plain;

            $blockOffset += 16;
        }

        $ctx->messageOffset = $messageOffset;
        $ctx->messageSum = $messageSum;
        $ctx->messageBlock = $blockIndex;
        $ctx->messageBuffer = substr($message, $blockOffset);
        
        return $plaintext;
    }
    
    function finalise(Context $ctx): string
    {
        if ($ctx->finalised) {
            throw new InvalidContextException('Final block has already been processed');
        }
        $ctx->finalised = true;
        
        $pad = '';
        $message = $ctx->messageBuffer;
        if (strlen($message) % 16) {
            $ctx->messageOffset ^= $ctx->lstar;

            $pad = $message ^ $this->encryptBlock($ctx->key, $ctx->messageOffset);
            
            if ($ctx->mode === Context::MODE_ENCRYPT) {
                $ctx->messageSum ^= $message . "\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
            }
            else {
                $ctx->messageSum ^= $pad . "\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
            }
        }

        $aad = $ctx->aadBuffer;
        if (strlen($aad) % 16) {
            $ctx->aadSum ^= $this->encryptBlock($ctx->key, $ctx->aadOffset ^ $ctx->lstar ^ ($aad . "\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\0"));
        }

        $ctx->messageBuffer = '';
        return $pad;
    }

    function tag(Context $ctx): string
    {
        return $ctx->aadSum ^ $this->encryptBlock($ctx->key, $ctx->messageSum ^ $ctx->messageOffset ^ $ctx->ldollar);
    }

    function verify(Context $ctx, string $tag, string $aad = ''): string
    {
        if (!hash_equals($this->tag($ctx, $aad), $tag)) {
            throw new AuthenticationException;
        }
    }
}

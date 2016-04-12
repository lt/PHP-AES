<?php declare(strict_types = 1);

namespace AES\Mode;

use AES\Cipher;
use AES\Context\OCB as Context;
use AES\Exception\BlockLengthException;
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
        $ctx->sum = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        $ctx->lstar = $this->encryptBlock($key, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
        $ctx->ldollar = $this->calc_L_i($ctx->lstar, 1);
        $ctx->blockIndex = 0;

        $nonce = str_pad($nonce, 16, "\0", STR_PAD_LEFT);
        $nonce[0] = chr(((self::TAGBYES << 3) % 128) << 1);
        $nonceOffset = 16 - self::NONCEBYTES - 1;
        $nonce[$nonceOffset] = $nonce[$nonceOffset] | "\1";
        $bottom = ord($nonce[15]) & 0x3f;
        $nonce[15] = $nonce[15] & "\xc0";

        $ktop = $this->encryptBlock($ctx->key, $nonce);
        list(, $stretch0, $stretch1, $stretch2) = unpack('J3', $ktop . (substr($ktop, 1, 8) ^ $ktop));

        $bottomMask = ~(-1 << $bottom);
        $offset = pack('J2',
            $stretch0 << $bottom | (($stretch1 >> (64 - $bottom)) & $bottomMask),
            $stretch1 << $bottom | (($stretch2 >> (64 - $bottom)) & $bottomMask)
        );

        $ctx->offset = $offset;

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

    private function hash(Context $ctx, string $message): string
    {
        $offset = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        $sum = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

        $messageOffset = 0;
        $messageLen = strlen($message);
        $blocks = $messageLen >> 4;
        for ($i = 1; $i <= $blocks; $i++, $messageOffset += 16) {
            $offset ^= $this->calc_L_i($ctx->ldollar, $i);
            $sum ^= $this->encryptBlock($ctx->key, $offset ^ substr($message, $messageOffset, 16));
        }

        if ($messageLen % 16) {
            $sum ^= $this->encryptBlock($ctx->key, $offset ^ $ctx->lstar ^ (substr($message, $messageOffset) . "\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"));
        }

        return $sum;
    }

    function encrypt(Context $ctx, string $message, bool $final = false): string
    {
        if ($ctx->finalised) {
            throw new InvalidContextException('Context cannot be reused after the final block has been processed');
        }

        if ($ctx->mode === Context::MODE_DECRYPT) {
            throw new InvalidContextException('Decryption context supplied to encryption method');
        }
        $ctx->mode = Context::MODE_ENCRYPT;

        $messageLen = strlen($message);
        $messageRemainder = $messageLen % 16;

        if ($messageRemainder && !$final) {
            throw new BlockLengthException('Message length must be a multiple of 16 when $final == false');
        }

        $offset = $ctx->offset;
        $sum = $ctx->sum;
        $blockIndex = $ctx->blockIndex;

        $out = '';
        $messageOffset = 0;
        $blocks = $messageLen >> 4;
        while ($blocks--) {
            $block = substr($message, $messageOffset, 16);
            $offset ^= $this->calc_L_i($ctx->ldollar, ++$blockIndex);

            $sum ^= $block;
            $out .= $offset ^ $this->encryptBlock($ctx->key, $offset ^ $block);

            $messageOffset += 16;
        }

        if ($final && $messageRemainder) {
            $ctx->finalised = true;

            $block = substr($message, $messageOffset);
            $offset ^= $ctx->lstar;

            $pad = $block ^ $this->encryptBlock($ctx->key, $offset);
            $sum ^= $block . "\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
            $out .= $pad;
        }

        $ctx->offset = $offset;
        $ctx->sum = $sum;
        $ctx->blockIndex = $blockIndex;

        return $out;
    }

    function decrypt(Context $ctx, string $message, bool $final = false): string
    {
        if ($ctx->finalised) {
            throw new InvalidContextException('Context cannot be reused after the final block has been processed');
        }

        if ($ctx->mode === Context::MODE_ENCRYPT) {
            throw new InvalidContextException('Encryption context supplied to decryption method');
        }
        $ctx->mode = Context::MODE_DECRYPT;

        $messageLen = strlen($message);
        $messageRemainder = $messageLen % 16;

        if ($messageRemainder && !$final) {
            throw new BlockLengthException('Message length must be a multiple of 16 when $final == false');
        }

        $offset = $ctx->offset;
        $sum = $ctx->sum;
        $blockIndex = $ctx->blockIndex;

        $out = '';
        $messageOffset = 0;
        $blocks = $messageLen >> 4;
        while ($blocks--) {
            $block = substr($message, $messageOffset, 16);
            $offset ^= $this->calc_L_i($ctx->ldollar, ++$blockIndex);

            $plain = $offset ^ $this->decryptBlock($ctx->key, $offset ^ $block);
            $sum ^= $plain;
            $out .= $plain;

            $messageOffset += 16;
        }

        if ($final && $messageRemainder) {
            $ctx->finalised = true;

            $tmp = substr($message, $messageOffset);
            $offset ^= $ctx->lstar;

            $pad = $tmp ^ $this->encryptBlock($ctx->key, $offset);
            $sum ^= $pad . "\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
            $out .= $pad;
        }

        $ctx->offset = $offset;
        $ctx->sum = $sum;
        $ctx->blockIndex = $blockIndex;
        
        return $out;
    }

    function tag(Context $ctx, string $aad = ''): string
    {
        return $this->hash($ctx, $aad) ^ $this->encryptBlock($ctx->key, $ctx->sum ^ $ctx->offset ^ $ctx->ldollar);
    }
}

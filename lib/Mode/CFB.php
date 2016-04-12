<?php declare(strict_types = 1);

namespace AES\Mode;

use AES\Cipher;
use AES\Context\CFB as Context;
use AES\Exception\InvalidContextException;
use AES\Key;

class CFB extends Cipher
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
        if ($ctx->mode === Context::MODE_DECRYPT) {
            throw new InvalidContextException('Decryption context supplied to encryption method');
        }
        $ctx->mode = Context::MODE_ENCRYPT;
        
        $keyStream = $ctx->buffer;

        // Since this is a stream mode the output doesn't have to be aligned to block boundaries.
        // However we only get a new IV when a block (i.e. keyStream) has been fully consumed.

        // It's possible that it may take several calls (i.e. short messages) to consume the block,
        // so the IV is built up as we go.

        // The len(iv) + len(keyStream) should always be equal to 16
        $out = $message ^ $keyStream;
        $iv = $ctx->state . $out;

        // One becomes '', the other becomes the remainder of itself
        $outLen = strlen($out);
        $message = substr($message, $outLen);
        $keyStream = substr($keyStream, $outLen);

        $offset = 0;

        // if the message was short and didn't consume the remaining
        // keyStream then 0 bytes are required and the loop is skipped
        $bytesRequired = strlen($message);
        $bytesOver = $bytesRequired % 16;

        $blocks = ($bytesRequired >> 4) + ($bytesOver > 0);
        while ($blocks--) {
            $keyStream = $this->encryptBlock($ctx->key, $iv);
            // len(iv) can be less than 16 on the last block
            $out .= $iv = $keyStream ^ substr($message, $offset, 16);
            $offset += 16;
        }

        $ctx->buffer = $bytesOver ? substr($keyStream, $bytesOver) : '';
        $ctx->state = $iv;

        return $out;
    }

    function decrypt(Context $ctx, string $message): string
    {
        if ($ctx->mode === Context::MODE_ENCRYPT) {
            throw new InvalidContextException('Encryption context supplied to decryption method');
        }
        $ctx->mode = Context::MODE_DECRYPT;

        $keyStream = $ctx->buffer;

        // Similar to encrypt, we only get a new iv for each block-aligned
        // piece of ciphertext, so we need to build it as we go in case of
        // many calls with small messages
        $out = $message ^ $keyStream;
        $iv = $ctx->state . substr($message, 0, strlen($out));

        $outLen = strlen($out);
        $message = substr($message, $outLen);
        $keyStream = substr($keyStream, $outLen);

        $offset = 0;

        $bytesRequired = strlen($message);
        $bytesOver = $bytesRequired % 16;

        $blocks = ($bytesRequired >> 4) + ($bytesOver > 0);
        while ($blocks--) {
            $keyStream = $this->encryptBlock($ctx->key, $iv);
            $out .= $keyStream ^ ($iv = substr($message, $offset, 16));
            $offset += 16;
        }

        $ctx->buffer = $bytesOver ? substr($keyStream, $bytesOver) : '';
        $ctx->state = $iv;

        return $out;
    }
} 

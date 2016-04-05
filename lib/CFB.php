<?php declare(strict_types = 1);

namespace AES;

class CFB extends Cipher
{
    private $key;
    private $iv;
    private $buffer = '';

    function __construct(Key $key, string $iv)
    {
        if (strlen($iv) !== 16) {
            throw new IVLengthException;
        }
        
        $this->key = $key;
        $this->iv = $iv;
    }
    
    function encrypt(string $message): string
    {
        $keyStream = $this->buffer;

        // Since this is a stream mode the output doesn't have to be aligned to block boundaries.
        // However we only get a new IV when a block (i.e. keyStream) has been fully consumed.

        // It's possible that it may take several calls (i.e. short messages) to consume the block,
        // so the IV is built up as we go.

        // The len(iv) + len(keyStream) should always be equal to 16
        $out = $message ^ $keyStream;
        $iv = $this->iv . $out;

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
            $keyStream = $this->encryptBlock($this->key, $iv);
            // len(iv) can be less than 16 on the last block
            $out .= $iv = $keyStream ^ substr($message, $offset, 16);
            $offset += 16;
        }

        $this->buffer = $bytesOver ? substr($keyStream, $bytesOver) : '';
        $this->iv = $iv;

        return $out;
    }

    function decrypt(string $message): string
    {
        $keyStream = $this->buffer;

        // Similar to encrypt, we only get a new iv for each block-aligned
        // piece of ciphertext, so we need to build it as we go in case of
        // many calls with small messages
        $out = $message ^ $keyStream;
        $iv = $this->iv . substr($message, 0, strlen($out));

        $outLen = strlen($out);
        $message = substr($message, $outLen);
        $keyStream = substr($keyStream, $outLen);

        $offset = 0;

        $bytesRequired = strlen($message);
        $bytesOver = $bytesRequired % 16;

        $blocks = ($bytesRequired >> 4) + ($bytesOver > 0);
        while ($blocks--) {
            $keyStream = $this->encryptBlock($this->key, $iv);
            $out .= $keyStream ^ ($iv = substr($message, $offset, 16));
            $offset += 16;
        }

        $this->buffer = $bytesOver ? substr($keyStream, $bytesOver) : '';
        $this->iv = $iv;

        return $out;
    }
} 

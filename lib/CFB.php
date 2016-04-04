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
        // However we only get a new IV when a block (keyStream) has been completely consumed.
        // It's possible that it may take several calls to consume the block, so the IV is built
        // up as we go.
        $out = $message ^ $keyStream;
        $iv = $this->iv . $out;

        $outLen = strlen($out);
        $message = substr($message, $outLen);
        $keyStream = substr($keyStream, $outLen);

        $offset = 0;

        $bytesRequired = strlen($message);
        $bytesOver = $bytesRequired % 16;

        $blocks = ($bytesRequired >> 4) + ($bytesOver > 0);
        while ($blocks--) {
            $keyStream = $this->encryptBlock($this->key, $iv);
            $out .= $iv = $keyStream ^ substr($message, $offset, 16);
            $offset += 16;
        }

        $this->buffer = substr($keyStream, $bytesRequired);
        $this->iv = $iv;

        return $out;
    }

    function decrypt(string $message): string
    {
        $keyStream = $this->buffer;

        $out = $message ^ $keyStream;
        $iv = $this->iv;
        $iv .= substr($message, 0, 16 - strlen($iv));

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

        $this->buffer = substr($keyStream, $bytesRequired);
        $this->iv = $iv;

        return $out;
    }
} 

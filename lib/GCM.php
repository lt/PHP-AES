<?php declare(strict_types = 1);

namespace AES;

use AES\Context\GCM\{
    Context,
    EncryptionContext,
    DecryptionContext
};
use AES\Exception\AuthenticationException;
use AES\Exception\InvalidContextException;
use AES\Exception\IVLengthException;

class GCM extends Cipher
{
    const R_HI = -2233785415175766016;

    private function init(Context $context, Key $key, string $nonce)
    {
        if (strlen($nonce) !== 12) {
            throw new IVLengthException;
        }

        $context->key = $key;
        $context->nonce = $nonce;

        $H = $this->encryptBlock($key, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
        list(, $context->H_hi, $context->H_lo) = unpack('J2', $H);
        
        $context->T = $this->encryptBlock($key, $nonce . "\0\0\0\1");
        $this->generateTable($context);
    }
    
    function reInit(Context $context, string $nonce)
    {
        $context->tag = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        $context->aadLen = 0;
        $context->aadBuffer = '';
        $context->messageLen = 0;
        $context->messageBuffer = '';
        $context->blockIndex = 1;
        $context->nonce = $nonce;
        $context->T = $this->encryptBlock($context->key, $nonce . "\0\0\0\1");
    }

    function initEncryption(Key $key, string $iv): EncryptionContext
    {
        $context = new EncryptionContext;
        $this->init($context, $key, $iv);
        return $context;
    }

    function initDecryption(Key $key, string $iv): DecryptionContext
    {
        $context = new DecryptionContext;
        $this->init($context, $key, $iv);
        return $context;
    }

    private function generateTable(Context $context)
    {
        $table = new \SplFixedArray(8192);
        $H_lo = $context->H_lo;
        $H_hi = $context->H_hi;
        $i = 0;

        // Avoid shifting Y left and then shifting back right by knowing where bits will be set
        for ($bitWindow = 8; $bitWindow <= 128; $bitWindow += 8) {
            for ($y = 0; $y < 256; $y++) {
                $result_lo = 0;
                $result_hi = 0;
                $x_lo = $H_lo;
                $x_hi = $H_hi;

                // Before the bit window we only shift/xor
                for ($bit = 127; $bit >= $bitWindow; $bit--) {
                    // 128 bit right shift and branchless add R to X if low bit of X is set
                    $multiplier = $x_lo & 1;
                    $x_lo = (($x_lo >> 1) & 0x7fffffffffffffff) | ($x_hi << 63);
                    $x_hi = (($x_hi >> 1) & 0x7fffffffffffffff) ^ (self::R_HI * $multiplier);
                }

                // During the bit window we perform additional operations
                for ($shift = 7; $shift >= 0; $bit--) {
                    // Branchless add X to result if current bit of Y is set
                    $multiplier = (($y >> $shift--) & 1);
                    $result_lo ^= $x_lo * $multiplier;
                    $result_hi ^= $x_hi * $multiplier;

                    // 128 bit right shift and branchless add R to X if low bit of X is set
                    $multiplier = $x_lo & 1;
                    $x_lo = (($x_lo >> 1) & 0x7fffffffffffffff) | ($x_hi << 63);
                    $x_hi = (($x_hi >> 1) & 0x7fffffffffffffff) ^ (self::R_HI * $multiplier);
                }

                // After the bit window we only shift/xor
                for (; $bit >= 0; $bit--) {
                    // 128 bit right shift and branchless add R to X if low bit of X is set
                    $multiplier = $x_lo & 1;
                    $x_lo = (($x_lo >> 1) & 0x7fffffffffffffff) | ($x_hi << 63);
                    $x_hi = (($x_hi >> 1) & 0x7fffffffffffffff) ^ (self::R_HI * $multiplier);
                }

                $table[$i++] = $result_hi;
                $table[$i++] = $result_lo;
            }
        }

        $context->table = $table;
    }

    private function mul($context, $value)
    {
        list(, $value_hi, $value_lo) = unpack('J2', $value);

        $result_lo = 0;
        $result_hi = 0;

        // Our precomuted table is contiguous to save hash table overhead
        // table[byteIndex][bitIndex][hi,lo] -> table[hi, lo, hi, lo]
        for ($byteIndex = 0; $byteIndex < 4096; $byteIndex += 512) {
            $bitIndex = ($value_lo & 0xff) << 1;
            $result_hi ^= $context->table[$byteIndex + $bitIndex++];
            $result_lo ^= $context->table[$byteIndex + $bitIndex];
            $value_lo >>= 8;
        }

        for (; $byteIndex < 8192; $byteIndex += 512) {
            $bitIndex = ($value_hi & 0xff) << 1;
            $result_hi ^= $context->table[$byteIndex + $bitIndex++];
            $result_lo ^= $context->table[$byteIndex + $bitIndex];
            $value_hi >>= 8;
        }

        return pack('J2', $result_hi, $result_lo);
    }

    function hash($context, string $message, string $aad = '')
    {
        $messageLen = strlen($message);
        $aadLen = strlen($aad);
        $tag = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

        // Process whole blocks of AAD
        $offset = 0;
        $blockCount = $aadLen >> 4;
        while ($blockCount--) {
            $tag = $this->mul($context, $tag ^ substr($aad, $offset, 16));
            $offset += 16;
        }

        // Process final partial block of AAD
        if ($aadLen % 16) {
            $tag ^= str_pad(substr($aad, $offset), 16, "\0", STR_PAD_RIGHT);
            $tag = $this->mul($context, $tag);
        }

        // Process whole blocks of message
        $offset = 0;
        $blockCount = $messageLen >> 4;
        while ($blockCount--) {
            $tag = $this->mul($context, $tag ^ substr($message, $offset, 16));
            $offset += 16;
        }

        // Process final partial block of message
        if ($messageLen % 16) {
            $tag ^= str_pad(substr($message, $offset), 16, "\0", STR_PAD_RIGHT);
            $tag = $this->mul($context, $tag);
        }

        $tag ^= pack('J2', $aadLen << 3, $messageLen << 3);
        $tag = $this->mul($context, $tag);
        
        return $tag;
    }

    function aad(Context $context, string $aad)
    {
        if (is_null($context->aadBuffer)) {
            throw new InvalidContextException('Cannot process more AAD after en/decryption has started.');
        }

        $aad = $context->aadBuffer . $aad;
        $aadLen = strlen($aad);
        $tag = $context->tag;

        $aadOffset = 0;
        $blockCount = $aadLen >> 4;
        while ($blockCount--) {
            $tag = $this->mul($context, $tag ^ substr($aad, $aadOffset, 16));
            $aadOffset += 16;
        }

        $context->tag = $tag;
        $context->aadLen += $aadOffset;
        $context->aadBuffer = substr($aad, $aadOffset);
    }
    
    private function finaliseAAD(Context $context)
    {
        if (!$context->aadBuffer) {
            return;
        }
        
        $tag = $context->tag;

        $tag ^= str_pad($context->aadBuffer, 16, "\0", STR_PAD_RIGHT);
        $tag = $this->mul($context, $tag);

        $context->aadLen += strlen($context->aadBuffer);
        $context->tag = $tag;
        $context->aadBuffer = null;
    }

    function streamEncrypt(EncryptionContext $context, string $message): string
    {
        $this->finaliseAAD($context);
        
        $message = $context->messageBuffer . $message;

        $key = $context->key;
        $tag = $context->tag;
        $nonce = $context->nonce;
        $blockIndex = $context->blockIndex;

        $ciphertext = '';
        $messageOffset = 0;
        $blockCount = (strlen($message) >> 4);
        while ($blockCount--) {
            $messageBlock = substr($message, $messageOffset, 16);
            
            $keyStream = $this->encryptBlock($key, $nonce . pack('N', ++$blockIndex));
            $encryptedBlock = $messageBlock ^ $keyStream;
            
            $tag = $this->mul($context, $encryptedBlock ^ $tag);
            $ciphertext .= $encryptedBlock;
            
            $messageOffset += 16;
        }

        $context->tag = $tag;
        $context->blockIndex = $blockIndex;
        $context->messageBuffer = substr($message, $messageOffset);
        $context->messageLen += $messageOffset;
        
        return $ciphertext;
    }

    function streamDecrypt(DecryptionContext $context, string $message): string
    {
        $this->finaliseAAD($context);

        $message = $context->messageBuffer . $message;

        $key = $context->key;
        $tag = $context->tag;
        $nonce = $context->nonce;
        $blockIndex = $context->blockIndex;

        $plaintext = '';
        $messageOffset = 0;
        $blockCount = (strlen($message) >> 4);
        while ($blockCount--) {
            $messageBlock = substr($message, $messageOffset, 16);
            $tag = $this->mul($context, $messageBlock ^ $tag);
            
            $keyStream = $this->encryptBlock($key, $nonce . pack('N', ++$blockIndex));
            $plaintext .= $messageBlock ^ $keyStream;

            $messageOffset += 16;
        }

        $context->tag = $tag;
        $context->messageBuffer = substr($message, $messageOffset);
        $context->messageLen += $messageOffset;

        return $plaintext;
    }

    function finalise(Context $context): string
    {
        if (is_null($context->messageBuffer)) {
            throw new InvalidContextException('Context already finalised.');
        }
        
        $output = '';
        $tag = $context->tag;
        
        if ($context->messageBuffer) {
            $keyStream = $this->encryptBlock($context->key, $context->nonce . pack('N', ++$context->blockIndex));
            $output = $context->messageBuffer ^ $keyStream;

            if ($context instanceof EncryptionContext) {
                $tag ^= str_pad($output, 16, "\0", STR_PAD_RIGHT);
            }
            else {
                $tag ^= str_pad($context->messageBuffer, 16, "\0", STR_PAD_RIGHT);
            }
            $tag = $this->mul($context, $tag);
            
            $context->messageLen += strlen($context->messageBuffer);
        }
        
        $context->messageBuffer = null;
        
        $tag ^= pack('J2', $context->aadLen << 3, $context->messageLen << 3);
        $tag = $this->mul($context, $tag);
        
        $context->tag = $tag;
        
        return $output;
    }

    function tag(Context $context)
    {
        return $context->T ^ $context->tag;
    }
    
    function verify(Context $context, string $tag)
    {
        if (!hash_equals($this->tag($context), $tag)) {
            throw new AuthenticationException;
        }
    }
    
    function encrypt(Key $key, string $nonce, string $aad, string $message): array
    {
        $context = $this->initEncryption($key, $nonce);

        $ciphertext = '';
        $blockIndex = 1;

        $bytesRequired = strlen($message);
        $blockCount = ($bytesRequired >> 4) + (($bytesRequired % 16) > 0);
        while ($blockCount--) {
            $ciphertext .= $this->encryptBlock($key, $nonce . pack('N', ++$blockIndex));
        }

        $ciphertext ^= $message;
        $hash = $this->hash($context, $ciphertext, $aad);

        return [
            $ciphertext,
            $context->T ^ $hash
        ];
    }

    function decrypt(Key $key, string $nonce, string $aad, string $message, string $tag): string
    {
        $context = $this->initDecryption($key, $nonce);
        $hash = $this->hash($context, $message, $aad);

        if (!hash_equals($context->T ^ $hash, $tag)) {
            throw new AuthenticationException;
        }

        $keyStream = '';
        $blockIndex = 1;

        $bytesRequired = strlen($message);
        $blockCount = ($bytesRequired >> 4) + (($bytesRequired % 16) > 0);
        while ($blockCount--) {
            $keyStream .= $this->encryptBlock($key, $nonce . pack('N', ++$blockIndex));
        }

        return $message ^ $keyStream;
    }
}

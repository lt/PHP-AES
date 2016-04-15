<?php declare(strict_types = 1);

namespace AES;

use AES\Context\OCB\{
    Context,
    EncryptionContext,
    DecryptionContext
};
use AES\Exception\{
    AuthenticationException,
    InvalidContextException,
    IVLengthException
};

class OCB extends Cipher
{
    const NONCEBYTES = 12;
    const TAGBYES = 16;

    const NULL_STR = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    const PAD_STR = "\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    private function init(Context $context, Key $key, string $nonce)
    {
        assert(self::NONCEBYTES > 1 && self::NONCEBYTES < 16);
        assert(self::TAGBYES > 1 && self::TAGBYES <= 16);

        if (strlen($nonce) !== self::NONCEBYTES) {
            throw new IVLengthException;
        }

        $context->key = $key;
        // Reference code defines L_* and L_$
        $context->lstar = $this->encryptBlock($key, self::NULL_STR);
        $context->ldollar = $this->calc_L_i($context->lstar, 1);

        $nonce = str_pad("\1" . $nonce, 16, "\0", STR_PAD_LEFT);
        $nonce[0] = chr(((self::TAGBYES << 3) % 128) << 1);
        $bottom = ord($nonce[15]) & 0x3f;
        $nonce[15] = $nonce[15] & "\xc0";

        $ktop = $this->encryptBlock($context->key, $nonce);
        list(, $stretch0, $stretch1, $stretch2) = unpack('J3', $ktop . (substr($ktop, 1, 8) ^ $ktop));

        $bottomMask = ~(-1 << $bottom);
        $messageOffset = pack('J2',
            $stretch0 << $bottom | (($stretch1 >> (64 - $bottom)) & $bottomMask),
            $stretch1 << $bottom | (($stretch2 >> (64 - $bottom)) & $bottomMask)
        );

        $context->cryptOffset = $messageOffset;
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

    function aad(Context $context, string $aad)
    {
        if ($context->finalised) {
            throw new InvalidContextException('Cannot process more data after finalise() has been called.');
        }

        $aad = $context->aadBuffer . $aad;

        $aadOffset = $context->aadOffset;
        $aadSum = $context->aadSum;
        $blockIndex = $context->aadBlock;

        $blockOffset = 0;
        $blockCount = strlen($aad) >> 4;
        while ($blockCount--) {
            $aadBlock = substr($aad, $blockOffset, 16);
            $aadOffset ^= $this->calc_L_i($context->ldollar, ++$blockIndex);

            $aadSum ^= $this->encryptBlock($context->key, $aadOffset ^ $aadBlock);

            $blockOffset += 16;
        }

        $context->aadOffset = $aadOffset;
        $context->aadSum = $aadSum;
        $context->aadBlock = $blockIndex;
        $context->aadBuffer = substr($aad, $blockOffset);
    }

    function encrypt(EncryptionContext $context, string $message): string
    {
        if ($context->finalised) {
            throw new InvalidContextException('Cannot process more data after finalise() has been called.');
        }

        $message = $context->cryptBuffer . $message;

        $cryptOffset = $context->cryptOffset;
        $cryptSum = $context->cryptSum;
        $blockIndex = $context->cryptIndex;

        $ciphertext = '';
        $messageOffset = 0;
        $blockCount = strlen($message) >> 4;
        while ($blockCount--) {
            $messageBlock = substr($message, $messageOffset, 16);
            $cryptOffset ^= $this->calc_L_i($context->ldollar, ++$blockIndex);

            $cryptSum ^= $messageBlock;
            $encryptedBlock = $cryptOffset ^ $this->encryptBlock($context->key, $cryptOffset ^ $messageBlock);
            $ciphertext .= $encryptedBlock;

            $messageOffset += 16;
        }

        $context->cryptOffset = $cryptOffset;
        $context->cryptSum = $cryptSum;
        $context->cryptIndex = $blockIndex;
        $context->cryptBuffer = substr($message, $messageOffset);

        return $ciphertext;
    }

    function decrypt(DecryptionContext $context, string $message): string
    {
        if ($context->finalised) {
            throw new InvalidContextException('Cannot process more data after finalise() has been called.');
        }

        $message = $context->cryptBuffer . $message;
        $cryptOffset = $context->cryptOffset;
        $cryptSum = $context->cryptSum;
        $blockIndex = $context->cryptIndex;

        $plaintext = '';
        $messageOffset = 0;
        $blockCount = strlen($message) >> 4;
        while ($blockCount--) {
            $messageBlock = substr($message, $messageOffset, 16);
            $cryptOffset ^= $this->calc_L_i($context->ldollar, ++$blockIndex);

            $decryptedBlock = $cryptOffset ^ $this->decryptBlock($context->key, $cryptOffset ^ $messageBlock);
            $cryptSum ^= $decryptedBlock;
            $plaintext .= $decryptedBlock;

            $messageOffset += 16;
        }

        $context->cryptOffset = $cryptOffset;
        $context->cryptSum = $cryptSum;
        $context->cryptIndex = $blockIndex;
        $context->cryptBuffer = substr($message, $messageOffset);
        
        return $plaintext;
    }
    
    function finalise(Context $context): string
    {
        if ($context->finalised) {
            throw new InvalidContextException('Final block has already been processed');
        }
        $context->finalised = true;
        
        $pad = '';
        $message = $context->cryptBuffer;
        if (strlen($message) % 16) {
            $context->cryptOffset ^= $context->lstar;

            $pad = $message ^ $this->encryptBlock($context->key, $context->cryptOffset);
            
            if ($context instanceof EncryptionContext) {
                $context->cryptSum ^= $message . self::PAD_STR;
            }
            else {
                $context->cryptSum ^= $pad . self::PAD_STR;
            }
        }

        $aad = $context->aadBuffer;
        if (strlen($aad) % 16) {
            $context->aadSum ^= $this->encryptBlock($context->key, $context->aadOffset ^ $context->lstar ^ ($aad . self::PAD_STR));
        }

        return $pad;
    }

    function tag(Context $ctx): string
    {
        $tag = $ctx->aadSum ^ $this->encryptBlock($ctx->key, $ctx->cryptSum ^ $ctx->cryptOffset ^ $ctx->ldollar);
        return substr($tag, 0, self::TAGBYES);
    }

    function verify(Context $ctx, string $tag): string
    {
        if (!hash_equals($this->tag($ctx), $tag)) {
            throw new AuthenticationException;
        }
    }
}

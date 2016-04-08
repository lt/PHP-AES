<?php declare(strict_types = 1);

namespace AES\Mode;

use AES\Cipher;
use AES\Key;

class OCB extends Cipher
{
    const KEYBYTES = 16;
    const NONCEBYTES = 12;
    const TAGBYES = 16;
    
    private $key;
    private $nonce;

    function __construct(Key $key, string $nonce)
    {
        $this->key = $key;
        $this->nonce = $nonce;
    }

    private function double(string $block): string
    {
        $out = '';
        for ($i = 0; $i < 15; $i++) {
            $out .= chr((ord($block[$i]) << 1) | (ord($block[$i + 1]) >> 7));
        }

        return $out . chr((ord($block[15]) << 1) ^ ((ord($block[0]) >> 7) * 135));
    }

    private function calc_L_i(string $ldollar, int $i): string
    {
        $l = $this->double($ldollar);

        for (; ($i & 1) === 0; $i >>= 1) {
            $l = $this->double($l);
        }

        return $l;
    }

    private function hash(string $aad): string
    {
        $abytes = strlen($aad);

        $lstar = $this->encryptBlock($this->key, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
        $ldollar = $this->double($lstar);

        $sum = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        $offset = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

        $in = 0;
        $blocks = $abytes >> 4;
        for ($i = 1; $i <= $blocks; $i++, $in += 16) {
            $tmp = $this->calc_L_i($ldollar, $i);
            $offset = $offset ^ $tmp;
            $tmp = $offset ^ substr($aad, $in, 16);
            $tmp = $this->encryptBlock($this->key, $tmp);
            $sum = $sum ^ $tmp;
        }

        $abytes %= 16;
        if ($abytes) {
            $offset = $offset ^ $lstar;
            $tmp = substr($aad, $in);
            $tmp .= "\x80" . str_repeat("\0", 16 - $abytes - 1);
            $tmp = $offset ^ $tmp;
            $tmp = $this->encryptBlock($this->key, $tmp);
            $sum = $sum ^ $tmp;
        }

        return $sum;
    }
    
    function encrypt(string $message, string $aad): string
    {
        $lstar = $this->encryptBlock($this->key, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
        $ldollar = $this->double($lstar);

        $nonce = str_pad($this->nonce, 16, "\0", STR_PAD_LEFT);
        $nonce[0] = chr(((self::TAGBYES << 3) % 128) << 1);
        $nonceOffset = 16 - self::NONCEBYTES - 1;
        $nonce[$nonceOffset] = $nonce[$nonceOffset] | "\1";
        $bottom = ord($nonce[15]) & 0x3f;

        $nonce[15] = $nonce[15] & "\xc0";
        $ktop = $this->encryptBlock($this->key, $nonce);

        $stretch = $ktop;

        $stretch .= substr($ktop, 1, 8) ^ $ktop;
        $byteshift = (int)($bottom / 8);
        $bitshift = $bottom % 8;

        $offset = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        if ($bitshift != 0) {
            for ($i = 0; $i < 16; $i++) {
                $offset[$i] = chr((ord($stretch[$i + $byteshift]) << $bitshift) |
                    (ord($stretch[$i + $byteshift + 1]) >> (8 - $bitshift)));
            }
        }
        else {
            for ($i = 0; $i < 16; $i++) {
                $offset[$i] = $stretch[$i + $byteshift];
            }
        }

        $sum = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        $out = '';
        $in = 0;
        $messageLen = strlen($message);
        $blocks = $messageLen >> 4;
        for ($i = 1; $i <= $blocks; $i++, $in += 16) {
            $tmp = $this->calc_L_i($ldollar, $i);
            $offset = $offset ^ $tmp;
            $tmp = $offset ^ substr($message, $in, 16);
            $tmp = $this->encryptBlock($this->key, $tmp);
            $out .= $offset ^ $tmp;
            $sum = $sum ^ substr($message, $in, 16);
        }

        $messageLen %= 16;
        if ($messageLen) {
            $offset = $offset ^ $lstar;
            $pad = $this->encryptBlock($this->key, $offset);
            $tmp = substr($message, $in);
            $tmp .= "\x80" . str_repeat("\0", 16 - $messageLen - 1);
            $sum = $tmp ^ $sum;
            $pad = $tmp ^ $pad;
            $out .= substr($pad, 0, $messageLen);
        }

        $tmp = $sum ^ $offset;
        $tmp = $tmp ^ $ldollar;
        $tag = $this->encryptBlock($this->key, $tmp);
        $tmp = $this->hash($aad);

        $tag = $tmp ^ $tag;
        $out .= $tag;

        return $out;
    }

    function decrypt(string $message, string $aad): string
    {
        $messageLen = strlen($message);

        if ($messageLen < self::TAGBYES) {
            throw new \InvalidArgumentException('Invalid message');
        }

        $messageLen -= self::TAGBYES;

        $lstar = $this->encryptBlock($this->key, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
        $ldollar = $this->double($lstar);

        $nonce = str_pad($this->nonce, 16, "\0", STR_PAD_LEFT);
        $nonce[0] = chr(((self::TAGBYES << 3) % 128) << 1);
        $nonceOffset = 16 - self::NONCEBYTES - 1;
        $nonce[$nonceOffset] = $nonce[$nonceOffset] | "\1";
        $bottom = ord($nonce[15]) & 0x3f;

        $nonce[15] = $nonce[15] & "\xc0";
        $ktop = $this->encryptBlock($this->key, $nonce);

        $stretch = $ktop;

        $stretch .= substr($ktop, 1, 8) ^ $ktop;
        $byteshift = (int)($bottom / 8);
        $bitshift = $bottom % 8;

        $offset = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        if ($bitshift != 0) {
            for ($i = 0; $i < 16; $i++) {
                $offset[$i] = chr((ord($stretch[$i + $byteshift]) << $bitshift) |
                    (ord($stretch[$i + $byteshift + 1]) >> (8 - $bitshift)));
            }
        }
        else {
            for ($i = 0; $i < 16; $i++) {
                $offset[$i] = $stretch[$i + $byteshift];
            }
        }

        $sum = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        $out = '';
        $in = 0;
        $blocks = $messageLen >> 4;
        for ($i = 1; $i <= $blocks; $i++, $in += 16) {
            $tmp = $this->calc_L_i($ldollar, $i);
            $offset = $offset ^ $tmp;
            $tmp = $offset ^ substr($message, $in, 16);
            $tmp = $this->decryptBlock($this->key, $tmp);
            $out .= $offset ^ $tmp;
            $sum = $sum ^ substr($out, $in, 16);
        }

        $messageLen %= 16;
        if ($messageLen) {
            $offset = $offset ^ $lstar;
            $pad = $this->encryptBlock($this->key, $offset);
            $tmp = substr($message, $in, $messageLen) . substr($pad, $messageLen);
            $tmp = $pad ^ $tmp;
            $tmp[$messageLen] = "\x80";
            $out .= substr($tmp, 0, $messageLen);

            $sum = $tmp ^ $sum;
        }

        $tmp = $sum ^ $offset;
        $tmp = $tmp ^ $ldollar;
        $tag = $this->encryptBlock($this->key, $tmp);
        $tmp = $this->hash($aad);
        $tag = $tmp ^ $tag;

        return (substr($message, $in + $messageLen) === $tag) ? $out : false;
    }
}

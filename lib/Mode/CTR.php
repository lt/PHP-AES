<?php

namespace AES\Mode;

use AES\Cipher;
use AES\Context\CTR as Context;

class CTR
{
    function encrypt(Context $ctx, $message)
    {
        $t0 = \AES\MIXCOLUMNS_0;
        $t1 = \AES\MIXCOLUMNS_1;
        $t2 = \AES\MIXCOLUMNS_2;
        $t3 = \AES\MIXCOLUMNS_3;
        $s  = \AES\SUBBYTES;
        $rk = $ctx->RK;

        $messageLen = strlen($message);
        $keyStream = $ctx->buffer;
        $keyLen = $ctx->keyLen;
        $nonce = $ctx->nonce;

        if ($keyStream) {
            $offset = strlen($keyStream);
            $messageLen -= $offset;
            $out = $message ^ $keyStream;
        }
        else {
            $offset = 0;
            $out = '';
        }

        $messageRemainder = $messageLen % 16;
        $blocks = ($messageLen >> 4) + ($messageRemainder > 0);
        
        while ($blocks--) {
            $x0 = $nonce[0] ^ $rk[0];
            $x1 = $nonce[1] ^ $rk[1];
            $x2 = $nonce[2] ^ $rk[2];
            $x3 = $nonce[3] ^ $rk[3];

            for($i = 3; $i >= 0; $i--) {
                if (!++$nonce[$i]) {
                    break;
                }
            }

            $y0 = $t0[$x0 >> 24 & 0xff] ^ $t1[$x1 >> 16 & 0xff] ^ $t2[$x2 >> 8 & 0xff] ^ $t3[$x3 & 0xff] ^ $rk[4];
            $y1 = $t0[$x1 >> 24 & 0xff] ^ $t1[$x2 >> 16 & 0xff] ^ $t2[$x3 >> 8 & 0xff] ^ $t3[$x0 & 0xff] ^ $rk[5];
            $y2 = $t0[$x2 >> 24 & 0xff] ^ $t1[$x3 >> 16 & 0xff] ^ $t2[$x0 >> 8 & 0xff] ^ $t3[$x1 & 0xff] ^ $rk[6];
            $y3 = $t0[$x3 >> 24 & 0xff] ^ $t1[$x0 >> 16 & 0xff] ^ $t2[$x1 >> 8 & 0xff] ^ $t3[$x2 & 0xff] ^ $rk[7];
            $x0 = $t0[$y0 >> 24 & 0xff] ^ $t1[$y1 >> 16 & 0xff] ^ $t2[$y2 >> 8 & 0xff] ^ $t3[$y3 & 0xff] ^ $rk[8];
            $x1 = $t0[$y1 >> 24 & 0xff] ^ $t1[$y2 >> 16 & 0xff] ^ $t2[$y3 >> 8 & 0xff] ^ $t3[$y0 & 0xff] ^ $rk[9];
            $x2 = $t0[$y2 >> 24 & 0xff] ^ $t1[$y3 >> 16 & 0xff] ^ $t2[$y0 >> 8 & 0xff] ^ $t3[$y1 & 0xff] ^ $rk[10];
            $x3 = $t0[$y3 >> 24 & 0xff] ^ $t1[$y0 >> 16 & 0xff] ^ $t2[$y1 >> 8 & 0xff] ^ $t3[$y2 & 0xff] ^ $rk[11];
            $y0 = $t0[$x0 >> 24 & 0xff] ^ $t1[$x1 >> 16 & 0xff] ^ $t2[$x2 >> 8 & 0xff] ^ $t3[$x3 & 0xff] ^ $rk[12];
            $y1 = $t0[$x1 >> 24 & 0xff] ^ $t1[$x2 >> 16 & 0xff] ^ $t2[$x3 >> 8 & 0xff] ^ $t3[$x0 & 0xff] ^ $rk[13];
            $y2 = $t0[$x2 >> 24 & 0xff] ^ $t1[$x3 >> 16 & 0xff] ^ $t2[$x0 >> 8 & 0xff] ^ $t3[$x1 & 0xff] ^ $rk[14];
            $y3 = $t0[$x3 >> 24 & 0xff] ^ $t1[$x0 >> 16 & 0xff] ^ $t2[$x1 >> 8 & 0xff] ^ $t3[$x2 & 0xff] ^ $rk[15];
            $x0 = $t0[$y0 >> 24 & 0xff] ^ $t1[$y1 >> 16 & 0xff] ^ $t2[$y2 >> 8 & 0xff] ^ $t3[$y3 & 0xff] ^ $rk[16];
            $x1 = $t0[$y1 >> 24 & 0xff] ^ $t1[$y2 >> 16 & 0xff] ^ $t2[$y3 >> 8 & 0xff] ^ $t3[$y0 & 0xff] ^ $rk[17];
            $x2 = $t0[$y2 >> 24 & 0xff] ^ $t1[$y3 >> 16 & 0xff] ^ $t2[$y0 >> 8 & 0xff] ^ $t3[$y1 & 0xff] ^ $rk[18];
            $x3 = $t0[$y3 >> 24 & 0xff] ^ $t1[$y0 >> 16 & 0xff] ^ $t2[$y1 >> 8 & 0xff] ^ $t3[$y2 & 0xff] ^ $rk[19];
            $y0 = $t0[$x0 >> 24 & 0xff] ^ $t1[$x1 >> 16 & 0xff] ^ $t2[$x2 >> 8 & 0xff] ^ $t3[$x3 & 0xff] ^ $rk[20];
            $y1 = $t0[$x1 >> 24 & 0xff] ^ $t1[$x2 >> 16 & 0xff] ^ $t2[$x3 >> 8 & 0xff] ^ $t3[$x0 & 0xff] ^ $rk[21];
            $y2 = $t0[$x2 >> 24 & 0xff] ^ $t1[$x3 >> 16 & 0xff] ^ $t2[$x0 >> 8 & 0xff] ^ $t3[$x1 & 0xff] ^ $rk[22];
            $y3 = $t0[$x3 >> 24 & 0xff] ^ $t1[$x0 >> 16 & 0xff] ^ $t2[$x1 >> 8 & 0xff] ^ $t3[$x2 & 0xff] ^ $rk[23];
            $x0 = $t0[$y0 >> 24 & 0xff] ^ $t1[$y1 >> 16 & 0xff] ^ $t2[$y2 >> 8 & 0xff] ^ $t3[$y3 & 0xff] ^ $rk[24];
            $x1 = $t0[$y1 >> 24 & 0xff] ^ $t1[$y2 >> 16 & 0xff] ^ $t2[$y3 >> 8 & 0xff] ^ $t3[$y0 & 0xff] ^ $rk[25];
            $x2 = $t0[$y2 >> 24 & 0xff] ^ $t1[$y3 >> 16 & 0xff] ^ $t2[$y0 >> 8 & 0xff] ^ $t3[$y1 & 0xff] ^ $rk[26];
            $x3 = $t0[$y3 >> 24 & 0xff] ^ $t1[$y0 >> 16 & 0xff] ^ $t2[$y1 >> 8 & 0xff] ^ $t3[$y2 & 0xff] ^ $rk[27];
            $y0 = $t0[$x0 >> 24 & 0xff] ^ $t1[$x1 >> 16 & 0xff] ^ $t2[$x2 >> 8 & 0xff] ^ $t3[$x3 & 0xff] ^ $rk[28];
            $y1 = $t0[$x1 >> 24 & 0xff] ^ $t1[$x2 >> 16 & 0xff] ^ $t2[$x3 >> 8 & 0xff] ^ $t3[$x0 & 0xff] ^ $rk[29];
            $y2 = $t0[$x2 >> 24 & 0xff] ^ $t1[$x3 >> 16 & 0xff] ^ $t2[$x0 >> 8 & 0xff] ^ $t3[$x1 & 0xff] ^ $rk[30];
            $y3 = $t0[$x3 >> 24 & 0xff] ^ $t1[$x0 >> 16 & 0xff] ^ $t2[$x1 >> 8 & 0xff] ^ $t3[$x2 & 0xff] ^ $rk[31];
            $x0 = $t0[$y0 >> 24 & 0xff] ^ $t1[$y1 >> 16 & 0xff] ^ $t2[$y2 >> 8 & 0xff] ^ $t3[$y3 & 0xff] ^ $rk[32];
            $x1 = $t0[$y1 >> 24 & 0xff] ^ $t1[$y2 >> 16 & 0xff] ^ $t2[$y3 >> 8 & 0xff] ^ $t3[$y0 & 0xff] ^ $rk[33];
            $x2 = $t0[$y2 >> 24 & 0xff] ^ $t1[$y3 >> 16 & 0xff] ^ $t2[$y0 >> 8 & 0xff] ^ $t3[$y1 & 0xff] ^ $rk[34];
            $x3 = $t0[$y3 >> 24 & 0xff] ^ $t1[$y0 >> 16 & 0xff] ^ $t2[$y1 >> 8 & 0xff] ^ $t3[$y2 & 0xff] ^ $rk[35];
            $y0 = $t0[$x0 >> 24 & 0xff] ^ $t1[$x1 >> 16 & 0xff] ^ $t2[$x2 >> 8 & 0xff] ^ $t3[$x3 & 0xff] ^ $rk[36];
            $y1 = $t0[$x1 >> 24 & 0xff] ^ $t1[$x2 >> 16 & 0xff] ^ $t2[$x3 >> 8 & 0xff] ^ $t3[$x0 & 0xff] ^ $rk[37];
            $y2 = $t0[$x2 >> 24 & 0xff] ^ $t1[$x3 >> 16 & 0xff] ^ $t2[$x0 >> 8 & 0xff] ^ $t3[$x1 & 0xff] ^ $rk[38];
            $y3 = $t0[$x3 >> 24 & 0xff] ^ $t1[$x0 >> 16 & 0xff] ^ $t2[$x1 >> 8 & 0xff] ^ $t3[$x2 & 0xff] ^ $rk[39];
            if ($keyLen > 44) {
                $x0 = $t0[$y0 >> 24 & 0xff] ^ $t1[$y1 >> 16 & 0xff] ^ $t2[$y2 >> 8 & 0xff] ^ $t3[$y3 & 0xff] ^ $rk[40];
                $x1 = $t0[$y1 >> 24 & 0xff] ^ $t1[$y2 >> 16 & 0xff] ^ $t2[$y3 >> 8 & 0xff] ^ $t3[$y0 & 0xff] ^ $rk[41];
                $x2 = $t0[$y2 >> 24 & 0xff] ^ $t1[$y3 >> 16 & 0xff] ^ $t2[$y0 >> 8 & 0xff] ^ $t3[$y1 & 0xff] ^ $rk[42];
                $x3 = $t0[$y3 >> 24 & 0xff] ^ $t1[$y0 >> 16 & 0xff] ^ $t2[$y1 >> 8 & 0xff] ^ $t3[$y2 & 0xff] ^ $rk[43];
                $y0 = $t0[$x0 >> 24 & 0xff] ^ $t1[$x1 >> 16 & 0xff] ^ $t2[$x2 >> 8 & 0xff] ^ $t3[$x3 & 0xff] ^ $rk[44];
                $y1 = $t0[$x1 >> 24 & 0xff] ^ $t1[$x2 >> 16 & 0xff] ^ $t2[$x3 >> 8 & 0xff] ^ $t3[$x0 & 0xff] ^ $rk[45];
                $y2 = $t0[$x2 >> 24 & 0xff] ^ $t1[$x3 >> 16 & 0xff] ^ $t2[$x0 >> 8 & 0xff] ^ $t3[$x1 & 0xff] ^ $rk[46];
                $y3 = $t0[$x3 >> 24 & 0xff] ^ $t1[$x0 >> 16 & 0xff] ^ $t2[$x1 >> 8 & 0xff] ^ $t3[$x2 & 0xff] ^ $rk[47];
                if ($keyLen === 60) {
                    $x0 = $t0[$y0 >> 24 & 0xff] ^ $t1[$y1 >> 16 & 0xff] ^ $t2[$y2 >> 8 & 0xff] ^ $t3[$y3 & 0xff] ^ $rk[48];
                    $x1 = $t0[$y1 >> 24 & 0xff] ^ $t1[$y2 >> 16 & 0xff] ^ $t2[$y3 >> 8 & 0xff] ^ $t3[$y0 & 0xff] ^ $rk[49];
                    $x2 = $t0[$y2 >> 24 & 0xff] ^ $t1[$y3 >> 16 & 0xff] ^ $t2[$y0 >> 8 & 0xff] ^ $t3[$y1 & 0xff] ^ $rk[50];
                    $x3 = $t0[$y3 >> 24 & 0xff] ^ $t1[$y0 >> 16 & 0xff] ^ $t2[$y1 >> 8 & 0xff] ^ $t3[$y2 & 0xff] ^ $rk[51];
                    $y0 = $t0[$x0 >> 24 & 0xff] ^ $t1[$x1 >> 16 & 0xff] ^ $t2[$x2 >> 8 & 0xff] ^ $t3[$x3 & 0xff] ^ $rk[52];
                    $y1 = $t0[$x1 >> 24 & 0xff] ^ $t1[$x2 >> 16 & 0xff] ^ $t2[$x3 >> 8 & 0xff] ^ $t3[$x0 & 0xff] ^ $rk[53];
                    $y2 = $t0[$x2 >> 24 & 0xff] ^ $t1[$x3 >> 16 & 0xff] ^ $t2[$x0 >> 8 & 0xff] ^ $t3[$x1 & 0xff] ^ $rk[54];
                    $y3 = $t0[$x3 >> 24 & 0xff] ^ $t1[$x0 >> 16 & 0xff] ^ $t2[$x1 >> 8 & 0xff] ^ $t3[$x2 & 0xff] ^ $rk[55];
                }
            }

            $keyStream = pack('N4',
                (($s[$y0 >> 24 & 0xff] << 24) ^ ($s[$y1 >> 16 & 0xff] << 16) ^ ($s[$y2 >> 8 & 0xff] << 8) ^ $s[$y3 & 0xff]) ^ $rk[56],
                (($s[$y1 >> 24 & 0xff] << 24) ^ ($s[$y2 >> 16 & 0xff] << 16) ^ ($s[$y3 >> 8 & 0xff] << 8) ^ $s[$y0 & 0xff]) ^ $rk[57],
                (($s[$y2 >> 24 & 0xff] << 24) ^ ($s[$y3 >> 16 & 0xff] << 16) ^ ($s[$y0 >> 8 & 0xff] << 8) ^ $s[$y1 & 0xff]) ^ $rk[58],
                (($s[$y3 >> 24 & 0xff] << 24) ^ ($s[$y0 >> 16 & 0xff] << 16) ^ ($s[$y1 >> 8 & 0xff] << 8) ^ $s[$y2 & 0xff]) ^ $rk[59]
            );

            $out .= substr($message, $offset, 16) ^ $keyStream;

            $offset += 16;
        }

        if ($messageRemainder) {
            $ctx->buffer = substr($keyStream, $messageRemainder);
        }
        else {
            $ctx->buffer = '';
        }

        $ctx->nonce = $nonce;

        return $out;
    }

    function decrypt(Context $ctx, $message)
    {
        return $this->encrypt($ctx, $message);
    }
} 

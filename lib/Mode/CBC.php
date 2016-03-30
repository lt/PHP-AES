<?php

namespace AES\Mode;

use AES\Cipher;
use AES\Context\CBC as Context;

class CBC
{
    function encrypt(Context $ctx, $message)
    {
        $t0 = \AES\MIXCOLUMNS_0;
        $t1 = \AES\MIXCOLUMNS_1;
        $t2 = \AES\MIXCOLUMNS_2;
        $t3 = \AES\MIXCOLUMNS_3;
        $s  = \AES\SUBBYTES;
        $rk = $ctx->RK;

        $offset = 0;
        $out = '';
        $messageLen = strlen($message);
        $keyLen = $ctx->keyLen;
        $blocks = $messageLen >> 4;

        list($iv0, $iv1, $iv2, $iv3) = $ctx->IV;

        while ($blocks--) {
            list(, $x0, $x1, $x2, $x3) = unpack("@$offset/N4", $message);

            $x0 ^= $rk[0] ^ $iv0;
            $x1 ^= $rk[1] ^ $iv1;
            $x2 ^= $rk[2] ^ $iv2;
            $x3 ^= $rk[3] ^ $iv3;
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
            if ($keyLen > 16) {
                $x0 = $t0[$y0 >> 24 & 0xff] ^ $t1[$y1 >> 16 & 0xff] ^ $t2[$y2 >> 8 & 0xff] ^ $t3[$y3 & 0xff] ^ $rk[40];
                $x1 = $t0[$y1 >> 24 & 0xff] ^ $t1[$y2 >> 16 & 0xff] ^ $t2[$y3 >> 8 & 0xff] ^ $t3[$y0 & 0xff] ^ $rk[41];
                $x2 = $t0[$y2 >> 24 & 0xff] ^ $t1[$y3 >> 16 & 0xff] ^ $t2[$y0 >> 8 & 0xff] ^ $t3[$y1 & 0xff] ^ $rk[42];
                $x3 = $t0[$y3 >> 24 & 0xff] ^ $t1[$y0 >> 16 & 0xff] ^ $t2[$y1 >> 8 & 0xff] ^ $t3[$y2 & 0xff] ^ $rk[43];
                $y0 = $t0[$x0 >> 24 & 0xff] ^ $t1[$x1 >> 16 & 0xff] ^ $t2[$x2 >> 8 & 0xff] ^ $t3[$x3 & 0xff] ^ $rk[44];
                $y1 = $t0[$x1 >> 24 & 0xff] ^ $t1[$x2 >> 16 & 0xff] ^ $t2[$x3 >> 8 & 0xff] ^ $t3[$x0 & 0xff] ^ $rk[45];
                $y2 = $t0[$x2 >> 24 & 0xff] ^ $t1[$x3 >> 16 & 0xff] ^ $t2[$x0 >> 8 & 0xff] ^ $t3[$x1 & 0xff] ^ $rk[46];
                $y3 = $t0[$x3 >> 24 & 0xff] ^ $t1[$x0 >> 16 & 0xff] ^ $t2[$x1 >> 8 & 0xff] ^ $t3[$x2 & 0xff] ^ $rk[47];
                if ($keyLen === 32) {
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

            $out .= pack('N4',
                $iv0 = (($s[$y0 >> 24 & 0xff] << 24) ^ ($s[$y1 >> 16 & 0xff] << 16) ^ ($s[$y2 >> 8 & 0xff] << 8) ^ $s[$y3 & 0xff]) ^ $rk[56],
                $iv1 = (($s[$y1 >> 24 & 0xff] << 24) ^ ($s[$y2 >> 16 & 0xff] << 16) ^ ($s[$y3 >> 8 & 0xff] << 8) ^ $s[$y0 & 0xff]) ^ $rk[57],
                $iv2 = (($s[$y2 >> 24 & 0xff] << 24) ^ ($s[$y3 >> 16 & 0xff] << 16) ^ ($s[$y0 >> 8 & 0xff] << 8) ^ $s[$y1 & 0xff]) ^ $rk[58],
                $iv3 = (($s[$y3 >> 24 & 0xff] << 24) ^ ($s[$y0 >> 16 & 0xff] << 16) ^ ($s[$y1 >> 8 & 0xff] << 8) ^ $s[$y2 & 0xff]) ^ $rk[59]
            );

            $offset += 16;
        }

        $ctx->IV = [$iv0, $iv1, $iv2, $iv3];

        return $out;
    }

    function decrypt(Context $ctx, $message)
    {
        $t0 = \AES\MIXCOLUMNS_INVERSE_0;
        $t1 = \AES\MIXCOLUMNS_INVERSE_1;
        $t2 = \AES\MIXCOLUMNS_INVERSE_2;
        $t3 = \AES\MIXCOLUMNS_INVERSE_3;
        $s  = \AES\SUBBYTES_INVERSE;
        $rk = $ctx->RKi;

        $offset = 0;
        $out = '';
        $messageLen = strlen($message);
        $keyLen = $ctx->keyLen;
        $blocks = $messageLen >> 4;

        list($iv0, $iv1, $iv2, $iv3) = $ctx->IV;

        while ($blocks--) {
            list(, $x0, $x1, $x2, $x3) = unpack("@$offset/N4", $message);

            $uv0 = $x0;
            $uv1 = $x1;
            $uv2 = $x2;
            $uv3 = $x3;

            $x3 ^= $rk[59];
            $x2 ^= $rk[58];
            $x1 ^= $rk[57];
            $x0 ^= $rk[56];
            switch ($keyLen) {
                case 32:
                    $y3 = $t0[$x3 >> 24 & 0xff] ^ $t1[$x2 >> 16 & 0xff] ^ $t2[$x1 >> 8 & 0xff] ^ $t3[$x0 & 0xff] ^ $rk[55];
                    $y2 = $t0[$x2 >> 24 & 0xff] ^ $t1[$x1 >> 16 & 0xff] ^ $t2[$x0 >> 8 & 0xff] ^ $t3[$x3 & 0xff] ^ $rk[54];
                    $y1 = $t0[$x1 >> 24 & 0xff] ^ $t1[$x0 >> 16 & 0xff] ^ $t2[$x3 >> 8 & 0xff] ^ $t3[$x2 & 0xff] ^ $rk[53];
                    $y0 = $t0[$x0 >> 24 & 0xff] ^ $t1[$x3 >> 16 & 0xff] ^ $t2[$x2 >> 8 & 0xff] ^ $t3[$x1 & 0xff] ^ $rk[52];
                    $x3 = $t0[$y3 >> 24 & 0xff] ^ $t1[$y2 >> 16 & 0xff] ^ $t2[$y1 >> 8 & 0xff] ^ $t3[$y0 & 0xff] ^ $rk[51];
                    $x2 = $t0[$y2 >> 24 & 0xff] ^ $t1[$y1 >> 16 & 0xff] ^ $t2[$y0 >> 8 & 0xff] ^ $t3[$y3 & 0xff] ^ $rk[50];
                    $x1 = $t0[$y1 >> 24 & 0xff] ^ $t1[$y0 >> 16 & 0xff] ^ $t2[$y3 >> 8 & 0xff] ^ $t3[$y2 & 0xff] ^ $rk[49];
                    $x0 = $t0[$y0 >> 24 & 0xff] ^ $t1[$y3 >> 16 & 0xff] ^ $t2[$y2 >> 8 & 0xff] ^ $t3[$y1 & 0xff] ^ $rk[48];
                case 24:
                    $y3 = $t0[$x3 >> 24 & 0xff] ^ $t1[$x2 >> 16 & 0xff] ^ $t2[$x1 >> 8 & 0xff] ^ $t3[$x0 & 0xff] ^ $rk[47];
                    $y2 = $t0[$x2 >> 24 & 0xff] ^ $t1[$x1 >> 16 & 0xff] ^ $t2[$x0 >> 8 & 0xff] ^ $t3[$x3 & 0xff] ^ $rk[46];
                    $y1 = $t0[$x1 >> 24 & 0xff] ^ $t1[$x0 >> 16 & 0xff] ^ $t2[$x3 >> 8 & 0xff] ^ $t3[$x2 & 0xff] ^ $rk[45];
                    $y0 = $t0[$x0 >> 24 & 0xff] ^ $t1[$x3 >> 16 & 0xff] ^ $t2[$x2 >> 8 & 0xff] ^ $t3[$x1 & 0xff] ^ $rk[44];
                    $x3 = $t0[$y3 >> 24 & 0xff] ^ $t1[$y2 >> 16 & 0xff] ^ $t2[$y1 >> 8 & 0xff] ^ $t3[$y0 & 0xff] ^ $rk[43];
                    $x2 = $t0[$y2 >> 24 & 0xff] ^ $t1[$y1 >> 16 & 0xff] ^ $t2[$y0 >> 8 & 0xff] ^ $t3[$y3 & 0xff] ^ $rk[42];
                    $x1 = $t0[$y1 >> 24 & 0xff] ^ $t1[$y0 >> 16 & 0xff] ^ $t2[$y3 >> 8 & 0xff] ^ $t3[$y2 & 0xff] ^ $rk[41];
                    $x0 = $t0[$y0 >> 24 & 0xff] ^ $t1[$y3 >> 16 & 0xff] ^ $t2[$y2 >> 8 & 0xff] ^ $t3[$y1 & 0xff] ^ $rk[40];
            }
            $y3 = $t0[$x3 >> 24 & 0xff] ^ $t1[$x2 >> 16 & 0xff] ^ $t2[$x1 >> 8 & 0xff] ^ $t3[$x0 & 0xff] ^ $rk[39];
            $y2 = $t0[$x2 >> 24 & 0xff] ^ $t1[$x1 >> 16 & 0xff] ^ $t2[$x0 >> 8 & 0xff] ^ $t3[$x3 & 0xff] ^ $rk[38];
            $y1 = $t0[$x1 >> 24 & 0xff] ^ $t1[$x0 >> 16 & 0xff] ^ $t2[$x3 >> 8 & 0xff] ^ $t3[$x2 & 0xff] ^ $rk[37];
            $y0 = $t0[$x0 >> 24 & 0xff] ^ $t1[$x3 >> 16 & 0xff] ^ $t2[$x2 >> 8 & 0xff] ^ $t3[$x1 & 0xff] ^ $rk[36];
            $x3 = $t0[$y3 >> 24 & 0xff] ^ $t1[$y2 >> 16 & 0xff] ^ $t2[$y1 >> 8 & 0xff] ^ $t3[$y0 & 0xff] ^ $rk[35];
            $x2 = $t0[$y2 >> 24 & 0xff] ^ $t1[$y1 >> 16 & 0xff] ^ $t2[$y0 >> 8 & 0xff] ^ $t3[$y3 & 0xff] ^ $rk[34];
            $x1 = $t0[$y1 >> 24 & 0xff] ^ $t1[$y0 >> 16 & 0xff] ^ $t2[$y3 >> 8 & 0xff] ^ $t3[$y2 & 0xff] ^ $rk[33];
            $x0 = $t0[$y0 >> 24 & 0xff] ^ $t1[$y3 >> 16 & 0xff] ^ $t2[$y2 >> 8 & 0xff] ^ $t3[$y1 & 0xff] ^ $rk[32];
            $y3 = $t0[$x3 >> 24 & 0xff] ^ $t1[$x2 >> 16 & 0xff] ^ $t2[$x1 >> 8 & 0xff] ^ $t3[$x0 & 0xff] ^ $rk[31];
            $y2 = $t0[$x2 >> 24 & 0xff] ^ $t1[$x1 >> 16 & 0xff] ^ $t2[$x0 >> 8 & 0xff] ^ $t3[$x3 & 0xff] ^ $rk[30];
            $y1 = $t0[$x1 >> 24 & 0xff] ^ $t1[$x0 >> 16 & 0xff] ^ $t2[$x3 >> 8 & 0xff] ^ $t3[$x2 & 0xff] ^ $rk[29];
            $y0 = $t0[$x0 >> 24 & 0xff] ^ $t1[$x3 >> 16 & 0xff] ^ $t2[$x2 >> 8 & 0xff] ^ $t3[$x1 & 0xff] ^ $rk[28];
            $x3 = $t0[$y3 >> 24 & 0xff] ^ $t1[$y2 >> 16 & 0xff] ^ $t2[$y1 >> 8 & 0xff] ^ $t3[$y0 & 0xff] ^ $rk[27];
            $x2 = $t0[$y2 >> 24 & 0xff] ^ $t1[$y1 >> 16 & 0xff] ^ $t2[$y0 >> 8 & 0xff] ^ $t3[$y3 & 0xff] ^ $rk[26];
            $x1 = $t0[$y1 >> 24 & 0xff] ^ $t1[$y0 >> 16 & 0xff] ^ $t2[$y3 >> 8 & 0xff] ^ $t3[$y2 & 0xff] ^ $rk[25];
            $x0 = $t0[$y0 >> 24 & 0xff] ^ $t1[$y3 >> 16 & 0xff] ^ $t2[$y2 >> 8 & 0xff] ^ $t3[$y1 & 0xff] ^ $rk[24];
            $y3 = $t0[$x3 >> 24 & 0xff] ^ $t1[$x2 >> 16 & 0xff] ^ $t2[$x1 >> 8 & 0xff] ^ $t3[$x0 & 0xff] ^ $rk[23];
            $y2 = $t0[$x2 >> 24 & 0xff] ^ $t1[$x1 >> 16 & 0xff] ^ $t2[$x0 >> 8 & 0xff] ^ $t3[$x3 & 0xff] ^ $rk[22];
            $y1 = $t0[$x1 >> 24 & 0xff] ^ $t1[$x0 >> 16 & 0xff] ^ $t2[$x3 >> 8 & 0xff] ^ $t3[$x2 & 0xff] ^ $rk[21];
            $y0 = $t0[$x0 >> 24 & 0xff] ^ $t1[$x3 >> 16 & 0xff] ^ $t2[$x2 >> 8 & 0xff] ^ $t3[$x1 & 0xff] ^ $rk[20];
            $x3 = $t0[$y3 >> 24 & 0xff] ^ $t1[$y2 >> 16 & 0xff] ^ $t2[$y1 >> 8 & 0xff] ^ $t3[$y0 & 0xff] ^ $rk[19];
            $x2 = $t0[$y2 >> 24 & 0xff] ^ $t1[$y1 >> 16 & 0xff] ^ $t2[$y0 >> 8 & 0xff] ^ $t3[$y3 & 0xff] ^ $rk[18];
            $x1 = $t0[$y1 >> 24 & 0xff] ^ $t1[$y0 >> 16 & 0xff] ^ $t2[$y3 >> 8 & 0xff] ^ $t3[$y2 & 0xff] ^ $rk[17];
            $x0 = $t0[$y0 >> 24 & 0xff] ^ $t1[$y3 >> 16 & 0xff] ^ $t2[$y2 >> 8 & 0xff] ^ $t3[$y1 & 0xff] ^ $rk[16];
            $y3 = $t0[$x3 >> 24 & 0xff] ^ $t1[$x2 >> 16 & 0xff] ^ $t2[$x1 >> 8 & 0xff] ^ $t3[$x0 & 0xff] ^ $rk[15];
            $y2 = $t0[$x2 >> 24 & 0xff] ^ $t1[$x1 >> 16 & 0xff] ^ $t2[$x0 >> 8 & 0xff] ^ $t3[$x3 & 0xff] ^ $rk[14];
            $y1 = $t0[$x1 >> 24 & 0xff] ^ $t1[$x0 >> 16 & 0xff] ^ $t2[$x3 >> 8 & 0xff] ^ $t3[$x2 & 0xff] ^ $rk[13];
            $y0 = $t0[$x0 >> 24 & 0xff] ^ $t1[$x3 >> 16 & 0xff] ^ $t2[$x2 >> 8 & 0xff] ^ $t3[$x1 & 0xff] ^ $rk[12];
            $x3 = $t0[$y3 >> 24 & 0xff] ^ $t1[$y2 >> 16 & 0xff] ^ $t2[$y1 >> 8 & 0xff] ^ $t3[$y0 & 0xff] ^ $rk[11];
            $x2 = $t0[$y2 >> 24 & 0xff] ^ $t1[$y1 >> 16 & 0xff] ^ $t2[$y0 >> 8 & 0xff] ^ $t3[$y3 & 0xff] ^ $rk[10];
            $x1 = $t0[$y1 >> 24 & 0xff] ^ $t1[$y0 >> 16 & 0xff] ^ $t2[$y3 >> 8 & 0xff] ^ $t3[$y2 & 0xff] ^ $rk[9];
            $x0 = $t0[$y0 >> 24 & 0xff] ^ $t1[$y3 >> 16 & 0xff] ^ $t2[$y2 >> 8 & 0xff] ^ $t3[$y1 & 0xff] ^ $rk[8];
            $y3 = $t0[$x3 >> 24 & 0xff] ^ $t1[$x2 >> 16 & 0xff] ^ $t2[$x1 >> 8 & 0xff] ^ $t3[$x0 & 0xff] ^ $rk[7];
            $y2 = $t0[$x2 >> 24 & 0xff] ^ $t1[$x1 >> 16 & 0xff] ^ $t2[$x0 >> 8 & 0xff] ^ $t3[$x3 & 0xff] ^ $rk[6];
            $y1 = $t0[$x1 >> 24 & 0xff] ^ $t1[$x0 >> 16 & 0xff] ^ $t2[$x3 >> 8 & 0xff] ^ $t3[$x2 & 0xff] ^ $rk[5];
            $y0 = $t0[$x0 >> 24 & 0xff] ^ $t1[$x3 >> 16 & 0xff] ^ $t2[$x2 >> 8 & 0xff] ^ $t3[$x1 & 0xff] ^ $rk[4];

            $out .= pack('N4',
                $iv0 ^ (($s[$y0 >> 24 & 0xff] << 24) | ($s[$y3 >> 16 & 0xff] << 16) | ($s[$y2 >> 8 & 0xff] << 8) | $s[$y1 & 0xff]) ^ $rk[0],
                $iv1 ^ (($s[$y1 >> 24 & 0xff] << 24) | ($s[$y0 >> 16 & 0xff] << 16) | ($s[$y3 >> 8 & 0xff] << 8) | $s[$y2 & 0xff]) ^ $rk[1],
                $iv2 ^ (($s[$y2 >> 24 & 0xff] << 24) | ($s[$y1 >> 16 & 0xff] << 16) | ($s[$y0 >> 8 & 0xff] << 8) | $s[$y3 & 0xff]) ^ $rk[2],
                $iv3 ^ (($s[$y3 >> 24 & 0xff] << 24) | ($s[$y2 >> 16 & 0xff] << 16) | ($s[$y1 >> 8 & 0xff] << 8) | $s[$y0 & 0xff]) ^ $rk[3]
            );

            $iv0 = $uv0;
            $iv1 = $uv1;
            $iv2 = $uv2;
            $iv3 = $uv3;

            $offset += 16;
        }

        $ctx->IV = [$iv0, $iv1, $iv2, $iv3];

        return $out;
    }
}

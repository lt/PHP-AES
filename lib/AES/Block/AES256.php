<?php

namespace AES\Block;

use AES\Context;

class AES256 extends Cipher
{
    protected $eStop = 52;
    protected $dStart = 59;

    function init(Context $ctx, $key)
    {
        $t0 = $this->T0i;
        $t1 = $this->T1i;
        $t2 = $this->T2i;
        $t3 = $this->T3i;
        $s = $this->S;

        list(,$rk0, $rk1, $rk2, $rk3, $rk4, $rk5, $rk6, $rk7) = unpack('N8', $key);

        $rk = [$rk0, $rk1, $rk2, $rk3, $rk4, $rk5, $rk6, $rk7];
        $rki = [
            $rk0, $rk1, $rk2, $rk3,
            $t0[$s[$rk4 >> 24 & 0xff]] ^ $t1[$s[$rk4 >> 16 & 0xff]] ^ $t2[$s[$rk4 >> 8 & 0xff]] ^ $t3[$s[$rk4 & 0xff]],
            $t0[$s[$rk5 >> 24 & 0xff]] ^ $t1[$s[$rk5 >> 16 & 0xff]] ^ $t2[$s[$rk5 >> 8 & 0xff]] ^ $t3[$s[$rk5 & 0xff]],
            $t0[$s[$rk6 >> 24 & 0xff]] ^ $t1[$s[$rk6 >> 16 & 0xff]] ^ $t2[$s[$rk6 >> 8 & 0xff]] ^ $t3[$s[$rk6 & 0xff]],
            $t0[$s[$rk7 >> 24 & 0xff]] ^ $t1[$s[$rk7 >> 16 & 0xff]] ^ $t2[$s[$rk7 >> 8 & 0xff]] ^ $t3[$s[$rk7 & 0xff]]
        ];

        for ($i = 8, $rc = 1; $i < 56; $rc = ($rc << 1) % 0xe5) {
            $rk[$i] = $rk0 = $rk0 ^ ($s[$rk7 >> 24 & 0xff] | ($s[$rk7 & 0xff] << 8) | ($s[$rk7 >> 8 & 0xff] << 16) | (($s[$rk7 >> 16 & 0xff] ^ $rc) << 24));
            $rki[$i++] = $t0[$s[$rk0 >> 24 & 0xff]] ^ $t1[$s[$rk0 >> 16 & 0xff]] ^ $t2[$s[$rk0 >> 8 & 0xff]] ^ $t3[$s[$rk0 & 0xff]];
            $rk[$i] = $rk1 = $rk1 ^ $rk0;
            $rki[$i++] = $t0[$s[$rk1 >> 24 & 0xff]] ^ $t1[$s[$rk1 >> 16 & 0xff]] ^ $t2[$s[$rk1 >> 8 & 0xff]] ^ $t3[$s[$rk1 & 0xff]];
            $rk[$i] = $rk2 = $rk2 ^ $rk1;
            $rki[$i++] = $t0[$s[$rk2 >> 24 & 0xff]] ^ $t1[$s[$rk2 >> 16 & 0xff]] ^ $t2[$s[$rk2 >> 8 & 0xff]] ^ $t3[$s[$rk2 & 0xff]];
            $rk[$i] = $rk3 = $rk3 ^ $rk2;
            $rki[$i++] = $t0[$s[$rk3 >> 24 & 0xff]] ^ $t1[$s[$rk3 >> 16 & 0xff]] ^ $t2[$s[$rk3 >> 8 & 0xff]] ^ $t3[$s[$rk3 & 0xff]];
            $rk[$i] = $rk4 = $rk4 ^ ($s[$rk3 & 0xff] | ($s[$rk3 >> 8 & 0xff] << 8) | ($s[$rk3 >> 16 & 0xff] << 16) | ($s[$rk3 >> 24 & 0xff] << 24));
            $rki[$i++] = $t0[$s[$rk4 >> 24 & 0xff]] ^ $t1[$s[$rk4 >> 16 & 0xff]] ^ $t2[$s[$rk4 >> 8 & 0xff]] ^ $t3[$s[$rk4 & 0xff]];
            $rk[$i] = $rk5 = $rk5 ^ $rk4;
            $rki[$i++] = $t0[$s[$rk5 >> 24 & 0xff]] ^ $t1[$s[$rk5 >> 16 & 0xff]] ^ $t2[$s[$rk5 >> 8 & 0xff]] ^ $t3[$s[$rk5 & 0xff]];
            $rk[$i] = $rk6 = $rk6 ^ $rk5;
            $rki[$i++] = $t0[$s[$rk6 >> 24 & 0xff]] ^ $t1[$s[$rk6 >> 16 & 0xff]] ^ $t2[$s[$rk6 >> 8 & 0xff]] ^ $t3[$s[$rk6 & 0xff]];
            $rk[$i] = $rk7 = $rk7 ^ $rk6;
            $rki[$i++] = $t0[$s[$rk7 >> 24 & 0xff]] ^ $t1[$s[$rk7 >> 16 & 0xff]] ^ $t2[$s[$rk7 >> 8 & 0xff]] ^ $t3[$s[$rk7 & 0xff]];
        }

        $rk[56] = $rki[56] = $rk0 = $rk0 ^ ($s[$rk7 >> 24 & 0xff] | ($s[$rk7 & 0xff] << 8) | ($s[$rk7 >> 8 & 0xff] << 16) | (($s[$rk7 >> 16 & 0xff] ^ 0x40) << 24));
        $rk[57] = $rki[57] = $rk1 = $rk1 ^ $rk0;
        $rk[58] = $rki[58] = $rk2 = $rk2 ^ $rk1;
        $rk[59] = $rki[59] = $rk3 ^ $rk2;

        $ctx->RK = $rk;
        $ctx->RKi = $rki;
        $ctx->keyLength = 32;
        $ctx->blockCipher = $this;
    }
}

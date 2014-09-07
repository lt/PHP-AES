<?php

namespace AES\Block;

use AES\Context;

class AES192 extends Cipher
{
    protected $eStop = 44;
    protected $dStart = 51;

    function init(Context $ctx, $key)
    {
        $t0 = $this->T0i;
        $t1 = $this->T1i;
        $t2 = $this->T2i;
        $t3 = $this->T3i;
        $s = $this->S;

        list(,$rk0, $rk1, $rk2, $rk3, $rk4, $rk5) = unpack('N6', $key);

        $rk = [$rk0, $rk1, $rk2, $rk3, $rk4, $rk5];
        $rki = [
            $rk0, $rk1, $rk2, $rk3,
            $t0[$s[$rk4 >> 24 & 0xff]] ^ $t1[$s[$rk4 >> 16 & 0xff]] ^ $t2[$s[$rk4 >> 8 & 0xff]] ^ $t3[$s[$rk4 & 0xff]],
            $t0[$s[$rk5 >> 24 & 0xff]] ^ $t1[$s[$rk5 >> 16 & 0xff]] ^ $t2[$s[$rk5 >> 8 & 0xff]] ^ $t3[$s[$rk5 & 0xff]]
        ];

        for ($i = 6, $rc = 1; $i < 48; $rc = ($rc << 1) % 0xe5) {
            $rk[$i] = $rk0 = $rk0 ^ ($s[$rk5 >> 24 & 0xff] | ($s[$rk5 & 0xff] << 8) | ($s[$rk5 >> 8 & 0xff] << 16) | (($s[$rk5 >> 16 & 0xff] ^ $rc) << 24));
            $rki[$i++] = $t0[$s[$rk0 >> 24 & 0xff]] ^ $t1[$s[$rk0 >> 16 & 0xff]] ^ $t2[$s[$rk0 >> 8 & 0xff]] ^ $t3[$s[$rk0 & 0xff]];
            $rk[$i] = $rk1 = $rk1 ^ $rk0;
            $rki[$i++] = $t0[$s[$rk1 >> 24 & 0xff]] ^ $t1[$s[$rk1 >> 16 & 0xff]] ^ $t2[$s[$rk1 >> 8 & 0xff]] ^ $t3[$s[$rk1 & 0xff]];
            $rk[$i] = $rk2 = $rk2 ^ $rk1;
            $rki[$i++] = $t0[$s[$rk2 >> 24 & 0xff]] ^ $t1[$s[$rk2 >> 16 & 0xff]] ^ $t2[$s[$rk2 >> 8 & 0xff]] ^ $t3[$s[$rk2 & 0xff]];
            $rk[$i] = $rk3 = $rk3 ^ $rk2;
            $rki[$i++] = $t0[$s[$rk3 >> 24 & 0xff]] ^ $t1[$s[$rk3 >> 16 & 0xff]] ^ $t2[$s[$rk3 >> 8 & 0xff]] ^ $t3[$s[$rk3 & 0xff]];
            $rk[$i] = $rk4 = $rk4 ^ $rk3;
            $rki[$i++] = $t0[$s[$rk4 >> 24 & 0xff]] ^ $t1[$s[$rk4 >> 16 & 0xff]] ^ $t2[$s[$rk4 >> 8 & 0xff]] ^ $t3[$s[$rk4 & 0xff]];
            $rk[$i] = $rk5 = $rk5 ^ $rk4;
            $rki[$i++] = $t0[$s[$rk5 >> 24 & 0xff]] ^ $t1[$s[$rk5 >> 16 & 0xff]] ^ $t2[$s[$rk5 >> 8 & 0xff]] ^ $t3[$s[$rk5 & 0xff]];
        }

        $rk[48] = $rki[48] = $rk0 = $rk0 ^ ($s[$rk5 >> 24 & 0xff] | ($s[$rk5 & 0xff] << 8) | ($s[$rk5 >> 8 & 0xff] << 16) | (($s[$rk5 >> 16 & 0xff] ^ 0x80) << 24));
        $rk[49] = $rki[49] = $rk1 = $rk1 ^ $rk0;
        $rk[50] = $rki[50] = $rk2 = $rk2 ^ $rk1;
        $rk[51] = $rki[51] = $rk3 ^ $rk2;

        $ctx->RK = $rk;
        $ctx->RKi = $rki;
        $ctx->keyLength = 24;
        $ctx->blockCipher = $this;
    }
}

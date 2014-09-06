<?php

class AES128 extends AESBase
{
    function setKey($key)
    {
        $t0 = $this->T0i;
        $t1 = $this->T1i;
        $t2 = $this->T2i;
        $t3 = $this->T3i;
        $s = $this->S;

        list(,$rk0, $rk1, $rk2, $rk3) = unpack('N4', $key);

        $rk = $rki = [$rk0, $rk1, $rk2, $rk3];

        for ($i = 4, $rc = 1; $i < 40; $rc = ($rc << 1) % 0xe5) {
            $rk[$i] = $rk0 = $rk0 ^ ($s[$rk3 >> 24 & 0xff] | ($s[$rk3 & 0xff] << 8) | ($s[$rk3 >> 8 & 0xff] << 16) | (($s[$rk3 >> 16 & 0xff] ^ $rc) << 24));
            $rki[$i++] = $t0[$s[$rk0 >> 24 & 0xff]] ^ $t1[$s[$rk0 >> 16 & 0xff]] ^ $t2[$s[$rk0 >> 8 & 0xff]] ^ $t3[$s[$rk0 & 0xff]];
            $rk[$i] = $rk1 = $rk1 ^ $rk0;
            $rki[$i++] = $t0[$s[$rk1 >> 24 & 0xff]] ^ $t1[$s[$rk1 >> 16 & 0xff]] ^ $t2[$s[$rk1 >> 8 & 0xff]] ^ $t3[$s[$rk1 & 0xff]];
            $rk[$i] = $rk2 = $rk2 ^ $rk1;
            $rki[$i++] = $t0[$s[$rk2 >> 24 & 0xff]] ^ $t1[$s[$rk2 >> 16 & 0xff]] ^ $t2[$s[$rk2 >> 8 & 0xff]] ^ $t3[$s[$rk2 & 0xff]];
            $rk[$i] = $rk3 = $rk3 ^ $rk2;
            $rki[$i++] = $t0[$s[$rk3 >> 24 & 0xff]] ^ $t1[$s[$rk3 >> 16 & 0xff]] ^ $t2[$s[$rk3 >> 8 & 0xff]] ^ $t3[$s[$rk3 & 0xff]];
        }

        $rk[40] = $rki[40] = $rk0 = $rk0 ^ ($s[$rk3 >> 24 & 0xff] | ($s[$rk3 & 0xff] << 8) | ($s[$rk3 >> 8 & 0xff] << 16) | (($s[$rk3 >> 16 & 0xff] ^ $rc) << 24));
        $rk[41] = $rki[41] = $rk1 = $rk1 ^ $rk0;
        $rk[42] = $rki[42] = $rk2 = $rk2 ^ $rk1;
        $rk[43] = $rki[43] = $rk3 ^ $rk2;

        $this->RK = $rk;
        $this->RKi = $rki;
    }

    function encrypt($block)
    {
        $t0 = $this->T0;
        $t1 = $this->T1;
        $t2 = $this->T2;
        $t3 = $this->T3;
        $s = $this->S;
        $rk  = $this->RK;

        list(,$x0, $x1, $x2, $x3) = unpack('N4', $block);

        $x0 ^= $rk[0];
        $x1 ^= $rk[1];
        $x2 ^= $rk[2];
        $x3 ^= $rk[3];

        // r1
        $y0 = $t0[$x0 >> 24 & 0xff] ^ $t1[$x1 >> 16 & 0xff] ^ $t2[$x2 >> 8 & 0xff] ^ $t3[$x3 & 0xff] ^ $rk[4];
        $y1 = $t0[$x1 >> 24 & 0xff] ^ $t1[$x2 >> 16 & 0xff] ^ $t2[$x3 >> 8 & 0xff] ^ $t3[$x0 & 0xff] ^ $rk[5];
        $y2 = $t0[$x2 >> 24 & 0xff] ^ $t1[$x3 >> 16 & 0xff] ^ $t2[$x0 >> 8 & 0xff] ^ $t3[$x1 & 0xff] ^ $rk[6];
        $y3 = $t0[$x3 >> 24 & 0xff] ^ $t1[$x0 >> 16 & 0xff] ^ $t2[$x1 >> 8 & 0xff] ^ $t3[$x2 & 0xff] ^ $rk[7];

        // r2
        $x0 = $t0[$y0 >> 24 & 0xff] ^ $t1[$y1 >> 16 & 0xff] ^ $t2[$y2 >> 8 & 0xff] ^ $t3[$y3 & 0xff] ^ $rk[8];
        $x1 = $t0[$y1 >> 24 & 0xff] ^ $t1[$y2 >> 16 & 0xff] ^ $t2[$y3 >> 8 & 0xff] ^ $t3[$y0 & 0xff] ^ $rk[9];
        $x2 = $t0[$y2 >> 24 & 0xff] ^ $t1[$y3 >> 16 & 0xff] ^ $t2[$y0 >> 8 & 0xff] ^ $t3[$y1 & 0xff] ^ $rk[10];
        $x3 = $t0[$y3 >> 24 & 0xff] ^ $t1[$y0 >> 16 & 0xff] ^ $t2[$y1 >> 8 & 0xff] ^ $t3[$y2 & 0xff] ^ $rk[11];

        // r3
        $y0 = $t0[$x0 >> 24 & 0xff] ^ $t1[$x1 >> 16 & 0xff] ^ $t2[$x2 >> 8 & 0xff] ^ $t3[$x3 & 0xff] ^ $rk[12];
        $y1 = $t0[$x1 >> 24 & 0xff] ^ $t1[$x2 >> 16 & 0xff] ^ $t2[$x3 >> 8 & 0xff] ^ $t3[$x0 & 0xff] ^ $rk[13];
        $y2 = $t0[$x2 >> 24 & 0xff] ^ $t1[$x3 >> 16 & 0xff] ^ $t2[$x0 >> 8 & 0xff] ^ $t3[$x1 & 0xff] ^ $rk[14];
        $y3 = $t0[$x3 >> 24 & 0xff] ^ $t1[$x0 >> 16 & 0xff] ^ $t2[$x1 >> 8 & 0xff] ^ $t3[$x2 & 0xff] ^ $rk[15];

        // r4
        $x0 = $t0[$y0 >> 24 & 0xff] ^ $t1[$y1 >> 16 & 0xff] ^ $t2[$y2 >> 8 & 0xff] ^ $t3[$y3 & 0xff] ^ $rk[16];
        $x1 = $t0[$y1 >> 24 & 0xff] ^ $t1[$y2 >> 16 & 0xff] ^ $t2[$y3 >> 8 & 0xff] ^ $t3[$y0 & 0xff] ^ $rk[17];
        $x2 = $t0[$y2 >> 24 & 0xff] ^ $t1[$y3 >> 16 & 0xff] ^ $t2[$y0 >> 8 & 0xff] ^ $t3[$y1 & 0xff] ^ $rk[18];
        $x3 = $t0[$y3 >> 24 & 0xff] ^ $t1[$y0 >> 16 & 0xff] ^ $t2[$y1 >> 8 & 0xff] ^ $t3[$y2 & 0xff] ^ $rk[19];

        // r5
        $y0 = $t0[$x0 >> 24 & 0xff] ^ $t1[$x1 >> 16 & 0xff] ^ $t2[$x2 >> 8 & 0xff] ^ $t3[$x3 & 0xff] ^ $rk[20];
        $y1 = $t0[$x1 >> 24 & 0xff] ^ $t1[$x2 >> 16 & 0xff] ^ $t2[$x3 >> 8 & 0xff] ^ $t3[$x0 & 0xff] ^ $rk[21];
        $y2 = $t0[$x2 >> 24 & 0xff] ^ $t1[$x3 >> 16 & 0xff] ^ $t2[$x0 >> 8 & 0xff] ^ $t3[$x1 & 0xff] ^ $rk[22];
        $y3 = $t0[$x3 >> 24 & 0xff] ^ $t1[$x0 >> 16 & 0xff] ^ $t2[$x1 >> 8 & 0xff] ^ $t3[$x2 & 0xff] ^ $rk[23];

        // r6
        $x0 = $t0[$y0 >> 24 & 0xff] ^ $t1[$y1 >> 16 & 0xff] ^ $t2[$y2 >> 8 & 0xff] ^ $t3[$y3 & 0xff] ^ $rk[24];
        $x1 = $t0[$y1 >> 24 & 0xff] ^ $t1[$y2 >> 16 & 0xff] ^ $t2[$y3 >> 8 & 0xff] ^ $t3[$y0 & 0xff] ^ $rk[25];
        $x2 = $t0[$y2 >> 24 & 0xff] ^ $t1[$y3 >> 16 & 0xff] ^ $t2[$y0 >> 8 & 0xff] ^ $t3[$y1 & 0xff] ^ $rk[26];
        $x3 = $t0[$y3 >> 24 & 0xff] ^ $t1[$y0 >> 16 & 0xff] ^ $t2[$y1 >> 8 & 0xff] ^ $t3[$y2 & 0xff] ^ $rk[27];

        // r7
        $y0 = $t0[$x0 >> 24 & 0xff] ^ $t1[$x1 >> 16 & 0xff] ^ $t2[$x2 >> 8 & 0xff] ^ $t3[$x3 & 0xff] ^ $rk[28];
        $y1 = $t0[$x1 >> 24 & 0xff] ^ $t1[$x2 >> 16 & 0xff] ^ $t2[$x3 >> 8 & 0xff] ^ $t3[$x0 & 0xff] ^ $rk[29];
        $y2 = $t0[$x2 >> 24 & 0xff] ^ $t1[$x3 >> 16 & 0xff] ^ $t2[$x0 >> 8 & 0xff] ^ $t3[$x1 & 0xff] ^ $rk[30];
        $y3 = $t0[$x3 >> 24 & 0xff] ^ $t1[$x0 >> 16 & 0xff] ^ $t2[$x1 >> 8 & 0xff] ^ $t3[$x2 & 0xff] ^ $rk[31];

        // r8
        $x0 = $t0[$y0 >> 24 & 0xff] ^ $t1[$y1 >> 16 & 0xff] ^ $t2[$y2 >> 8 & 0xff] ^ $t3[$y3 & 0xff] ^ $rk[32];
        $x1 = $t0[$y1 >> 24 & 0xff] ^ $t1[$y2 >> 16 & 0xff] ^ $t2[$y3 >> 8 & 0xff] ^ $t3[$y0 & 0xff] ^ $rk[33];
        $x2 = $t0[$y2 >> 24 & 0xff] ^ $t1[$y3 >> 16 & 0xff] ^ $t2[$y0 >> 8 & 0xff] ^ $t3[$y1 & 0xff] ^ $rk[34];
        $x3 = $t0[$y3 >> 24 & 0xff] ^ $t1[$y0 >> 16 & 0xff] ^ $t2[$y1 >> 8 & 0xff] ^ $t3[$y2 & 0xff] ^ $rk[35];

        // r9
        $y0 = $t0[$x0 >> 24 & 0xff] ^ $t1[$x1 >> 16 & 0xff] ^ $t2[$x2 >> 8 & 0xff] ^ $t3[$x3 & 0xff] ^ $rk[36];
        $y1 = $t0[$x1 >> 24 & 0xff] ^ $t1[$x2 >> 16 & 0xff] ^ $t2[$x3 >> 8 & 0xff] ^ $t3[$x0 & 0xff] ^ $rk[37];
        $y2 = $t0[$x2 >> 24 & 0xff] ^ $t1[$x3 >> 16 & 0xff] ^ $t2[$x0 >> 8 & 0xff] ^ $t3[$x1 & 0xff] ^ $rk[38];
        $y3 = $t0[$x3 >> 24 & 0xff] ^ $t1[$x0 >> 16 & 0xff] ^ $t2[$x1 >> 8 & 0xff] ^ $t3[$x2 & 0xff] ^ $rk[39];

        // r10
        $x0 = $s[$y0 & 0xff] | ($s[$y0 >> 8 & 0xff] << 8) | ($s[$y0 >> 16 & 0xff] << 16) | $s[$y0 >> 24 & 0xff] << 24;
        $x1 = $s[$y1 & 0xff] | ($s[$y1 >> 8 & 0xff] << 8) | ($s[$y1 >> 16 & 0xff] << 16) | $s[$y1 >> 24 & 0xff] << 24;
        $x2 = $s[$y2 & 0xff] | ($s[$y2 >> 8 & 0xff] << 8) | ($s[$y2 >> 16 & 0xff] << 16) | $s[$y2 >> 24 & 0xff] << 24;
        $x3 = $s[$y3 & 0xff] | ($s[$y3 >> 8 & 0xff] << 8) | ($s[$y3 >> 16 & 0xff] << 16) | $s[$y3 >> 24 & 0xff] << 24;

        return pack('N4',
            ($x0 & 0xff000000) ^ ($x1 & 0xff0000) ^ ($x2 & 0xff00) ^ ($x3 & 0xff) ^ $rk[40],
            ($x1 & 0xff000000) ^ ($x2 & 0xff0000) ^ ($x3 & 0xff00) ^ ($x0 & 0xff) ^ $rk[41],
            ($x2 & 0xff000000) ^ ($x3 & 0xff0000) ^ ($x0 & 0xff00) ^ ($x1 & 0xff) ^ $rk[42],
            ($x3 & 0xff000000) ^ ($x0 & 0xff0000) ^ ($x1 & 0xff00) ^ ($x2 & 0xff) ^ $rk[43]
        );
    }

    function decrypt($block)
    {
        $t0 = $this->T0i;
        $t1 = $this->T1i;
        $t2 = $this->T2i;
        $t3 = $this->T3i;
        $s = $this->Si;
        $rk  = $this->RKi;

        list(,$x0, $x1, $x2, $x3) = unpack('N4', $block);

        $x0 ^= $rk[40];
        $x1 ^= $rk[41];
        $x2 ^= $rk[42];
        $x3 ^= $rk[43];

        // r1
        $y0 = $t0[$x0 >> 24 & 0xff] ^ $t1[$x3 >> 16 & 0xff] ^ $t2[$x2 >> 8 & 0xff] ^ $t3[$x1 & 0xff] ^ $rk[36];
        $y1 = $t0[$x1 >> 24 & 0xff] ^ $t1[$x0 >> 16 & 0xff] ^ $t2[$x3 >> 8 & 0xff] ^ $t3[$x2 & 0xff] ^ $rk[37];
        $y2 = $t0[$x2 >> 24 & 0xff] ^ $t1[$x1 >> 16 & 0xff] ^ $t2[$x0 >> 8 & 0xff] ^ $t3[$x3 & 0xff] ^ $rk[38];
        $y3 = $t0[$x3 >> 24 & 0xff] ^ $t1[$x2 >> 16 & 0xff] ^ $t2[$x1 >> 8 & 0xff] ^ $t3[$x0 & 0xff] ^ $rk[39];

        // r2
        $x0 = $t0[$y0 >> 24 & 0xff] ^ $t1[$y3 >> 16 & 0xff] ^ $t2[$y2 >> 8 & 0xff] ^ $t3[$y1 & 0xff] ^ $rk[32];
        $x1 = $t0[$y1 >> 24 & 0xff] ^ $t1[$y0 >> 16 & 0xff] ^ $t2[$y3 >> 8 & 0xff] ^ $t3[$y2 & 0xff] ^ $rk[33];
        $x2 = $t0[$y2 >> 24 & 0xff] ^ $t1[$y1 >> 16 & 0xff] ^ $t2[$y0 >> 8 & 0xff] ^ $t3[$y3 & 0xff] ^ $rk[34];
        $x3 = $t0[$y3 >> 24 & 0xff] ^ $t1[$y2 >> 16 & 0xff] ^ $t2[$y1 >> 8 & 0xff] ^ $t3[$y0 & 0xff] ^ $rk[35];

        // r3
        $y0 = $t0[$x0 >> 24 & 0xff] ^ $t1[$x3 >> 16 & 0xff] ^ $t2[$x2 >> 8 & 0xff] ^ $t3[$x1 & 0xff] ^ $rk[28];
        $y1 = $t0[$x1 >> 24 & 0xff] ^ $t1[$x0 >> 16 & 0xff] ^ $t2[$x3 >> 8 & 0xff] ^ $t3[$x2 & 0xff] ^ $rk[29];
        $y2 = $t0[$x2 >> 24 & 0xff] ^ $t1[$x1 >> 16 & 0xff] ^ $t2[$x0 >> 8 & 0xff] ^ $t3[$x3 & 0xff] ^ $rk[30];
        $y3 = $t0[$x3 >> 24 & 0xff] ^ $t1[$x2 >> 16 & 0xff] ^ $t2[$x1 >> 8 & 0xff] ^ $t3[$x0 & 0xff] ^ $rk[31];

        // r4
        $x0 = $t0[$y0 >> 24 & 0xff] ^ $t1[$y3 >> 16 & 0xff] ^ $t2[$y2 >> 8 & 0xff] ^ $t3[$y1 & 0xff] ^ $rk[24];
        $x1 = $t0[$y1 >> 24 & 0xff] ^ $t1[$y0 >> 16 & 0xff] ^ $t2[$y3 >> 8 & 0xff] ^ $t3[$y2 & 0xff] ^ $rk[25];
        $x2 = $t0[$y2 >> 24 & 0xff] ^ $t1[$y1 >> 16 & 0xff] ^ $t2[$y0 >> 8 & 0xff] ^ $t3[$y3 & 0xff] ^ $rk[26];
        $x3 = $t0[$y3 >> 24 & 0xff] ^ $t1[$y2 >> 16 & 0xff] ^ $t2[$y1 >> 8 & 0xff] ^ $t3[$y0 & 0xff] ^ $rk[27];

        // r5
        $y0 = $t0[$x0 >> 24 & 0xff] ^ $t1[$x3 >> 16 & 0xff] ^ $t2[$x2 >> 8 & 0xff] ^ $t3[$x1 & 0xff] ^ $rk[20];
        $y1 = $t0[$x1 >> 24 & 0xff] ^ $t1[$x0 >> 16 & 0xff] ^ $t2[$x3 >> 8 & 0xff] ^ $t3[$x2 & 0xff] ^ $rk[21];
        $y2 = $t0[$x2 >> 24 & 0xff] ^ $t1[$x1 >> 16 & 0xff] ^ $t2[$x0 >> 8 & 0xff] ^ $t3[$x3 & 0xff] ^ $rk[22];
        $y3 = $t0[$x3 >> 24 & 0xff] ^ $t1[$x2 >> 16 & 0xff] ^ $t2[$x1 >> 8 & 0xff] ^ $t3[$x0 & 0xff] ^ $rk[23];

        // r6
        $x0 = $t0[$y0 >> 24 & 0xff] ^ $t1[$y3 >> 16 & 0xff] ^ $t2[$y2 >> 8 & 0xff] ^ $t3[$y1 & 0xff] ^ $rk[16];
        $x1 = $t0[$y1 >> 24 & 0xff] ^ $t1[$y0 >> 16 & 0xff] ^ $t2[$y3 >> 8 & 0xff] ^ $t3[$y2 & 0xff] ^ $rk[17];
        $x2 = $t0[$y2 >> 24 & 0xff] ^ $t1[$y1 >> 16 & 0xff] ^ $t2[$y0 >> 8 & 0xff] ^ $t3[$y3 & 0xff] ^ $rk[18];
        $x3 = $t0[$y3 >> 24 & 0xff] ^ $t1[$y2 >> 16 & 0xff] ^ $t2[$y1 >> 8 & 0xff] ^ $t3[$y0 & 0xff] ^ $rk[19];

        // r7
        $y0 = $t0[$x0 >> 24 & 0xff] ^ $t1[$x3 >> 16 & 0xff] ^ $t2[$x2 >> 8 & 0xff] ^ $t3[$x1 & 0xff] ^ $rk[12];
        $y1 = $t0[$x1 >> 24 & 0xff] ^ $t1[$x0 >> 16 & 0xff] ^ $t2[$x3 >> 8 & 0xff] ^ $t3[$x2 & 0xff] ^ $rk[13];
        $y2 = $t0[$x2 >> 24 & 0xff] ^ $t1[$x1 >> 16 & 0xff] ^ $t2[$x0 >> 8 & 0xff] ^ $t3[$x3 & 0xff] ^ $rk[14];
        $y3 = $t0[$x3 >> 24 & 0xff] ^ $t1[$x2 >> 16 & 0xff] ^ $t2[$x1 >> 8 & 0xff] ^ $t3[$x0 & 0xff] ^ $rk[15];

        // r8
        $x0 = $t0[$y0 >> 24 & 0xff] ^ $t1[$y3 >> 16 & 0xff] ^ $t2[$y2 >> 8 & 0xff] ^ $t3[$y1 & 0xff] ^ $rk[8];
        $x1 = $t0[$y1 >> 24 & 0xff] ^ $t1[$y0 >> 16 & 0xff] ^ $t2[$y3 >> 8 & 0xff] ^ $t3[$y2 & 0xff] ^ $rk[9];
        $x2 = $t0[$y2 >> 24 & 0xff] ^ $t1[$y1 >> 16 & 0xff] ^ $t2[$y0 >> 8 & 0xff] ^ $t3[$y3 & 0xff] ^ $rk[10];
        $x3 = $t0[$y3 >> 24 & 0xff] ^ $t1[$y2 >> 16 & 0xff] ^ $t2[$y1 >> 8 & 0xff] ^ $t3[$y0 & 0xff] ^ $rk[11];

        // r9
        $y0 = $t0[$x0 >> 24 & 0xff] ^ $t1[$x3 >> 16 & 0xff] ^ $t2[$x2 >> 8 & 0xff] ^ $t3[$x1 & 0xff] ^ $rk[4];
        $y1 = $t0[$x1 >> 24 & 0xff] ^ $t1[$x0 >> 16 & 0xff] ^ $t2[$x3 >> 8 & 0xff] ^ $t3[$x2 & 0xff] ^ $rk[5];
        $y2 = $t0[$x2 >> 24 & 0xff] ^ $t1[$x1 >> 16 & 0xff] ^ $t2[$x0 >> 8 & 0xff] ^ $t3[$x3 & 0xff] ^ $rk[6];
        $y3 = $t0[$x3 >> 24 & 0xff] ^ $t1[$x2 >> 16 & 0xff] ^ $t2[$x1 >> 8 & 0xff] ^ $t3[$x0 & 0xff] ^ $rk[7];

        // r10
        $x0 = $s[$y0 & 0xff] | ($s[$y0 >> 8 & 0xff] << 8) | ($s[$y0 >> 16 & 0xff] << 16) | $s[$y0 >> 24 & 0xff] << 24;
        $x1 = $s[$y1 & 0xff] | ($s[$y1 >> 8 & 0xff] << 8) | ($s[$y1 >> 16 & 0xff] << 16) | $s[$y1 >> 24 & 0xff] << 24;
        $x2 = $s[$y2 & 0xff] | ($s[$y2 >> 8 & 0xff] << 8) | ($s[$y2 >> 16 & 0xff] << 16) | $s[$y2 >> 24 & 0xff] << 24;
        $x3 = $s[$y3 & 0xff] | ($s[$y3 >> 8 & 0xff] << 8) | ($s[$y3 >> 16 & 0xff] << 16) | $s[$y3 >> 24 & 0xff] << 24;

        return pack('N4',
            ($x0 & 0xff000000) ^ ($x1 & 0xff0000) ^ ($x2 & 0xff00) ^ ($x3 & 0xff) ^ $rk[0],
            ($x3 & 0xff000000) ^ ($x0 & 0xff0000) ^ ($x1 & 0xff00) ^ ($x2 & 0xff) ^ $rk[1],
            ($x2 & 0xff000000) ^ ($x3 & 0xff0000) ^ ($x0 & 0xff00) ^ ($x1 & 0xff) ^ $rk[2],
            ($x1 & 0xff000000) ^ ($x2 & 0xff0000) ^ ($x3 & 0xff00) ^ ($x0 & 0xff) ^ $rk[3]
        );
    }
}

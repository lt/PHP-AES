<?php declare(strict_types = 1);

namespace AES;

abstract class Cipher
{
    private function mixColumns(int $a, int $b, int $c, int $d): int
    {
        return MIXCOLUMNS_0[$a >> 24       ] ^
               MIXCOLUMNS_1[$b >> 16 & 0xff] ^
               MIXCOLUMNS_2[$c >>  8 & 0xff] ^
               MIXCOLUMNS_3[$d       & 0xff];
    }

    private function mixColumnsInverse(int $a, int $b, int $c, int $d): int
    {
        return MIXCOLUMNS_INVERSE_0[$a >> 24       ] ^
               MIXCOLUMNS_INVERSE_1[$b >> 16 & 0xff] ^
               MIXCOLUMNS_INVERSE_2[$c >>  8 & 0xff] ^
               MIXCOLUMNS_INVERSE_3[$d       & 0xff];
    }

    private function subBytes(int $a, int $b, int $c, int $d): int
    {
        return (SUBBYTES[$a >> 24       ] << 24) |
               (SUBBYTES[$b >> 16 & 0xff] << 16) |
               (SUBBYTES[$c >>  8 & 0xff] <<  8) |
                SUBBYTES[$d       & 0xff];
    }

    private function subBytesInverse(int $a, int $b, int $c, int $d): int
    {
        return (SUBBYTES_INVERSE[$a >> 24       ] << 24) |
               (SUBBYTES_INVERSE[$b >> 16 & 0xff] << 16) |
               (SUBBYTES_INVERSE[$c >>  8 & 0xff] <<  8) |
                SUBBYTES_INVERSE[$d       & 0xff];
    }

    protected function encryptBlock(Key $key, string $block): string
    {
        $k = $key->encryptionKey();

        list(, $a, $b, $c, $d) = unpack('N4', $block);

        $a ^= $k[0];
        $b ^= $k[1];
        $c ^= $k[2];
        $d ^= $k[3];

        $i = 4;
        $rounds = ($key->bits() >> 5) + 5;
        while ($rounds--) {
            list($a, $b, $c, $d) = [
                $this->mixColumns($a, $b, $c, $d) ^ $k[$i++],
                $this->mixColumns($b, $c, $d, $a) ^ $k[$i++],
                $this->mixColumns($c, $d, $a, $b) ^ $k[$i++],
                $this->mixColumns($d, $a, $b, $c) ^ $k[$i++]
            ];
        }

        return pack('N4',
            $this->subBytes($a, $b, $c, $d) ^ $k[56],
            $this->subBytes($b, $c, $d, $a) ^ $k[57],
            $this->subBytes($c, $d, $a, $b) ^ $k[58],
            $this->subBytes($d, $a, $b, $c) ^ $k[59]
        );
    }

    protected function decryptBlock(Key $key, string $block): string
    {
        $k = $key->decryptionKey();

        list(, $a, $b, $c, $d) = unpack('N4', $block);

        $d ^= $k[59];
        $c ^= $k[58];
        $b ^= $k[57];
        $a ^= $k[56];

        $i = ($key->bits() >> 3) + 23;
        while ($i > 3) {
            list($d, $c, $b, $a) = [
                $this->mixColumnsInverse($d, $c, $b, $a) ^ $k[$i--],
                $this->mixColumnsInverse($c, $b, $a, $d) ^ $k[$i--],
                $this->mixColumnsInverse($b, $a, $d, $c) ^ $k[$i--],
                $this->mixColumnsInverse($a, $d, $c, $b) ^ $k[$i--],
            ];
        }

        return pack('N4',
            $this->subBytesInverse($a, $d, $c, $b) ^ $k[0],
            $this->subBytesInverse($b, $a, $d, $c) ^ $k[1],
            $this->subBytesInverse($c, $b, $a, $d) ^ $k[2],
            $this->subBytesInverse($d, $c, $b, $a) ^ $k[3]
        );
    }
}

<?php declare(strict_types = 1);

/*
 * NIST's AES Known Answer Test does not include vectors for CTR
 * These vectors are from NIST Special Publication 800-38A 
 */

namespace AES\Test;

use AES\CTR;
use AES\Key;

class CTR128 extends \PHPUnit_Framework_TestCase
{
    function testEncrypt()
    {
        $key = new Key(hex2bin('2b7e151628aed2a6abf7158809cf4f3c'));
        $ctr = new CTR();
        $result = $ctr->encrypt($key, hex2bin('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'), hex2bin('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710'));
        $this->assertSame(hex2bin('874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee'), $result);
    }

    function testDecrypt()
    {
        $key = new Key(hex2bin('2b7e151628aed2a6abf7158809cf4f3c'));
        $ctr = new CTR();
        $result = $ctr->decrypt($key, hex2bin('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'), hex2bin('874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee'));
        $this->assertSame(hex2bin('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710'), $result);
    }
}

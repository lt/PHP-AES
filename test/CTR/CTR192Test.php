<?php declare(strict_types = 1);

/*
 * NIST's AES Known Answer Test does not include vectors for CTR
 * These vectors are from NIST Special Publication 800-38A 
 */

namespace AES\Test;

use AES\CTR;
use AES\Key;

class CTR192 extends \PHPUnit_Framework_TestCase
{
    function testEncrypt()
    {
        $key = new Key(hex2bin('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b'));
        $ctr = new CTR();
        $ctx = $ctr->initEncryption($key, hex2bin('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'));
        $result = $ctr->encrypt($ctx, hex2bin('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710'));
        $this->assertSame(hex2bin('1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050'), $result);
    }

    function testDecrypt()
    {
        $key = new Key(hex2bin('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b'));
        $ctr = new CTR();
        $ctx = $ctr->initDecryption($key, hex2bin('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'));
        $result = $ctr->decrypt($ctx, hex2bin('1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050'));
        $this->assertSame(hex2bin('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710'), $result);
    }
}

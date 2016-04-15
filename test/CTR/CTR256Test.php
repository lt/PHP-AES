<?php declare(strict_types = 1);

/*
 * NIST's AES Known Answer Test does not include vectors for CTR
 * These vectors are from NIST Special Publication 800-38A 
 */

namespace AES\Test;

use AES\CTR;
use AES\Key;

class CTR256 extends \PHPUnit_Framework_TestCase
{
    function testEncrypt()
    {
        $key = new Key(hex2bin('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'));
        $ctr = new CTR();
        $ctx = $ctr->initEncryption($key, hex2bin('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'));
        $result = $ctr->encrypt($ctx, hex2bin('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710'));
        $this->assertSame(hex2bin('601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6'), $result);
    }

    function testDecrypt()
    {
        $key = new Key(hex2bin('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'));
        $ctr = new CTR();
        $ctx = $ctr->initDecryption($key, hex2bin('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'));
        $result = $ctr->decrypt($ctx, hex2bin('601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6'));
        $this->assertSame(hex2bin('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710'), $result);
    }
}

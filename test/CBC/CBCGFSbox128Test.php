<?php

# CAVS 11.1
# Config info for aes_values
# AESVS GFSbox test data for CBC
# State : Encrypt and Decrypt
# Key Length : 128
# Generated on Fri Apr 22 15:11:33 2011

namespace AES\Test;

use AES\Mode\CBC;
use AES\Key;

class CBCGFSbox128 extends \PHPUnit_Framework_TestCase
{
    function caseProvider()
    {
        return [
            ['00000000000000000000000000000000', '00000000000000000000000000000000', 'f34481ec3cc627bacd5dc3fb08f273e6', '0336763e966d92595a567cc9ce537f5e'],
            ['00000000000000000000000000000000', '00000000000000000000000000000000', '9798c4640bad75c7c3227db910174e72', 'a9a1631bf4996954ebc093957b234589'],
            ['00000000000000000000000000000000', '00000000000000000000000000000000', '96ab5c2ff612d9dfaae8c31f30c42168', 'ff4f8391a6a40ca5b25d23bedd44a597'],
            ['00000000000000000000000000000000', '00000000000000000000000000000000', '6a118a874519e64e9963798a503f1d35', 'dc43be40be0e53712f7e2bf5ca707209'],
            ['00000000000000000000000000000000', '00000000000000000000000000000000', 'cb9fceec81286ca3e989bd979b0cb284', '92beedab1895a94faa69b632e5cc47ce'],
            ['00000000000000000000000000000000', '00000000000000000000000000000000', 'b26aeb1874e47ca8358ff22378f09144', '459264f4798f6a78bacb89c15ed3d601'],
            ['00000000000000000000000000000000', '00000000000000000000000000000000', '58c8e00b2631686d54eab84b91f0aca1', '08a4e2efec8a8e3312ca7460b9040bbf']
        ];
    }

    /**
     * @dataProvider caseProvider
     */
    function testEncrypt($key, $iv, $plaintext, $ciphertext)
    {
        $cbc = new CBC(new Key(hex2bin($key)), hex2bin($iv));
        $result = $cbc->encrypt(hex2bin($plaintext));
        $this->assertSame(hex2bin($ciphertext), $result);
    }

    /**
     * @dataProvider caseProvider
     */
    function testDecrypt($key, $iv, $plaintext, $ciphertext)
    {
        $cbc = new CBC(new Key(hex2bin($key)), hex2bin($iv));
        $result = $cbc->decrypt(hex2bin($ciphertext));
        $this->assertSame(hex2bin($plaintext), $result);
    }
}

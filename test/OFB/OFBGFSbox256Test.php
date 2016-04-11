<?php

# CAVS 11.1
# Config info for aes_values
# AESVS GFSbox test data for OFB
# State : Encrypt and Decrypt
# Key Length : 256
# Generated on Fri Apr 22 15:12:03 2011

namespace AES\Test;

use AES\Mode\OFB;
use AES\Key;

class OFBGFSbox256 extends \PHPUnit_Framework_TestCase
{
    function caseProvider()
    {
        return [
            ['0000000000000000000000000000000000000000000000000000000000000000', '014730f80ac625fe84f026c60bfd547d', '00000000000000000000000000000000', '5c9d844ed46f9885085e5d6a4f94c7d7'],
            ['0000000000000000000000000000000000000000000000000000000000000000', '0b24af36193ce4665f2825d7b4749c98', '00000000000000000000000000000000', 'a9ff75bd7cf6613d3731c77c3b6d0c04'],
            ['0000000000000000000000000000000000000000000000000000000000000000', '761c1fe41a18acf20d241650611d90f1', '00000000000000000000000000000000', '623a52fcea5d443e48d9181ab32c7421'],
            ['0000000000000000000000000000000000000000000000000000000000000000', '8a560769d605868ad80d819bdba03771', '00000000000000000000000000000000', '38f2c7ae10612415d27ca190d27da8b4'],
            ['0000000000000000000000000000000000000000000000000000000000000000', '91fbef2d15a97816060bee1feaa49afe', '00000000000000000000000000000000', '1bc704f1bce135ceb810341b216d7abe']
        ];
    }

    /**
     * @dataProvider caseProvider
     */
    function testEncrypt($key, $iv, $plaintext, $ciphertext)
    {
        $key = new Key(hex2bin($key));
        $ofb = new OFB;
        $ctx = $ofb->init($key, hex2bin($iv));
        $result = $ofb->encrypt($ctx, hex2bin($plaintext));
        $this->assertSame(hex2bin($ciphertext), $result);
    }

    /**
     * @dataProvider caseProvider
     */
    function testDecrypt($key, $iv, $plaintext, $ciphertext)
    {
        $key = new Key(hex2bin($key));
        $ofb = new OFB;
        $ctx = $ofb->init($key, hex2bin($iv));
        $result = $ofb->decrypt($ctx, hex2bin($ciphertext));
        $this->assertSame(hex2bin($plaintext), $result);
    }
}

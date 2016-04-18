<?php

# CAVS 11.1
# Config info for aes_values
# AESVS GFSbox test data for OFB
# State : Encrypt and Decrypt
# Key Length : 192
# Generated on Fri Apr 22 15:12:01 2011

namespace AES\Test;

use AES\OFB;
use AES\Key;

class OFBGFSbox192 extends \PHPUnit_Framework_TestCase
{
    function caseProvider()
    {
        return [
            ['000000000000000000000000000000000000000000000000', '1b077a6af4b7f98229de786d7516b639', '00000000000000000000000000000000', '275cfc0413d8ccb70513c3859b1d0f72'],
            ['000000000000000000000000000000000000000000000000', '9c2d8842e5f48f57648205d39a239af1', '00000000000000000000000000000000', 'c9b8135ff1b5adc413dfd053b21bd96d'],
            ['000000000000000000000000000000000000000000000000', 'bff52510095f518ecca60af4205444bb', '00000000000000000000000000000000', '4a3650c3371ce2eb35e389a171427440'],
            ['000000000000000000000000000000000000000000000000', '51719783d3185a535bd75adc65071ce1', '00000000000000000000000000000000', '4f354592ff7c8847d2d0870ca9481b7c'],
            ['000000000000000000000000000000000000000000000000', '26aa49dcfe7629a8901a69a9914e6dfd', '00000000000000000000000000000000', 'd5e08bf9a182e857cf40b3a36ee248cc'],
            ['000000000000000000000000000000000000000000000000', '941a4773058224e1ef66d10e0a6ee782', '00000000000000000000000000000000', '067cd9d3749207791841562507fa9626']
        ];
    }

    /**
     * @dataProvider caseProvider
     */
    function testEncrypt($key, $iv, $plaintext, $ciphertext)
    {
        $key = new Key(hex2bin($key));
        $ofb = new OFB;
        $result = $ofb->encrypt($key, hex2bin($iv), hex2bin($plaintext));
        $this->assertSame(hex2bin($ciphertext), $result);
    }

    /**
     * @dataProvider caseProvider
     */
    function testDecrypt($key, $iv, $plaintext, $ciphertext)
    {
        $key = new Key(hex2bin($key));
        $ofb = new OFB;
        $result = $ofb->decrypt($key, hex2bin($iv), hex2bin($ciphertext));
        $this->assertSame(hex2bin($plaintext), $result);
    }
}

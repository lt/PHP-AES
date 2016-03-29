<?php

namespace AES\Test;

use AES\Padding\PKCS7;

class PKCS7Test extends \PHPUnit_Framework_TestCase
{
    function goodPadProvider()
    {
        return [
            ['', "\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"],
            ['a', "\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f"],
            ['aa', "\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e"],
            ['aaa', "\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d"],
            ['aaaa', "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"],
            ['aaaaa', "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"],
            ['aaaaaa', "\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a"],
            ['aaaaaaa', "\x09\x09\x09\x09\x09\x09\x09\x09\x09"],
            ['aaaaaaaa', "\x08\x08\x08\x08\x08\x08\x08\x08"],
            ['aaaaaaaaa', "\x07\x07\x07\x07\x07\x07\x07"],
            ['aaaaaaaaaa', "\x06\x06\x06\x06\x06\x06"],
            ['aaaaaaaaaaa', "\x05\x05\x05\x05\x05"],
            ['aaaaaaaaaaaa', "\x04\x04\x04\x04"],
            ['aaaaaaaaaaaaa', "\x03\x03\x03"],
            ['aaaaaaaaaaaaaa', "\x02\x02"],
            ['aaaaaaaaaaaaaaa', "\x01"],
            ['aaaaaaaaaaaaaaaa', "\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"],
            ["aaaaaaaa\x04\x04\x04\x04", "\x04\x04\x04\x04"]
        ];
    }

    function badPadProvider()
    {
        return [
            ['', "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"],
            ['a', "\x01"],
            ['aaaaaaaa', "\x04\x04\x04\x04"],
            ['aaaaaaaa', "\x08\0\0\0\0\0\0\x08"],
        ];
    }

    /**
     * @dataProvider goodPadProvider
     */
    function testGetPadding($message, $expected)
    {
        $scheme = new PKCS7();
        $result = $scheme->getPadding($message);
        $this->assertSame($expected, $result);
    }

    /**
     * @dataProvider goodPadProvider
     */
    function testGetPadLen($message, $expected)
    {
        $scheme = new PKCS7();
        $result = $scheme->getPadLen($message . $expected);
        $this->assertSame(16 - (strlen($message) % 16), $result);
    }

    /**
     * @expectedException \Exception
     * @dataProvider badPadProvider
     */
    function testBadGetPadLen($message, $expected)
    {
        $scheme = new PKCS7();
        $scheme->getPadLen($message . $expected);
    }
} 

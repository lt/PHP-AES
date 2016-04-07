<?php

namespace AES\Test;

use AES\Padding\ISOIEC7816;

class ISOIEC7816Test extends \PHPUnit_Framework_TestCase
{
    function goodPadProvider()
    {
        return [
            ['', "\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"],
            ['a', "\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\0"],
            ['aa', "\x80\0\0\0\0\0\0\0\0\0\0\0\0\0"],
            ['aaa', "\x80\0\0\0\0\0\0\0\0\0\0\0\0"],
            ['aaaa', "\x80\0\0\0\0\0\0\0\0\0\0\0"],
            ['aaaaa', "\x80\0\0\0\0\0\0\0\0\0\0"],
            ['aaaaaa', "\x80\0\0\0\0\0\0\0\0\0"],
            ['aaaaaaa', "\x80\0\0\0\0\0\0\0\0"],
            ['aaaaaaaa', "\x80\0\0\0\0\0\0\0"],
            ['aaaaaaaaa', "\x80\0\0\0\0\0\0"],
            ['aaaaaaaaaa', "\x80\0\0\0\0\0"],
            ['aaaaaaaaaaa', "\x80\0\0\0\0"],
            ['aaaaaaaaaaaa', "\x80\0\0\0"],
            ['aaaaaaaaaaaaa', "\x80\0\0"],
            ['aaaaaaaaaaaaaa', "\x80\0"],
            ['aaaaaaaaaaaaaaa', "\x80"],
            ['aaaaaaaaaaaaaaaa', "\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"],
            ["aaaaaaaa\x80\0\0\0", "\x80\0\0\0"]
        ];
    }

    function badPadProvider()
    {
        return [
            ['', "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"],
            ['a', "\x80"],
            ['aaaaaaaaaaaa', "\x80\0\1\0"],
        ];
    }

    /**
     * @dataProvider goodPadProvider
     */
    function testGetPadding($message, $expected)
    {
        $scheme = new ISOIEC7816();
        $result = $scheme->getPadding($message);
        $this->assertSame($expected, $result);
    }

    /**
     * @dataProvider goodPadProvider
     */
    function testGetPadLen($message, $expected)
    {
        $scheme = new ISOIEC7816();
        $result = $scheme->getPaddingLength($message . $expected);
        $this->assertSame(16 - (strlen($message) % 16), $result);
    }

    /**
     * @expectedException \AES\Exception\InvalidPaddingException
     * @dataProvider badPadProvider
     */
    function testBadGetPadLen($message, $expected)
    {
        $scheme = new ISOIEC7816();
        $scheme->getPaddingLength($message . $expected);
    }
} 

<?php

namespace AES\Test;

use AES\Padding\ANSIX923;

class ANSIX923Test extends \PHPUnit_Framework_TestCase
{
    function goodPadProvider()
    {
        return [
            ['', "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x10"],
            ['a', "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0f"],
            ['aa', "\0\0\0\0\0\0\0\0\0\0\0\0\0\x0e"],
            ['aaa', "\0\0\0\0\0\0\0\0\0\0\0\0\x0d"],
            ['aaaa', "\0\0\0\0\0\0\0\0\0\0\0\x0c"],
            ['aaaaa', "\0\0\0\0\0\0\0\0\0\0\x0b"],
            ['aaaaaa', "\0\0\0\0\0\0\0\0\0\x0a"],
            ['aaaaaaa', "\0\0\0\0\0\0\0\0\x09"],
            ['aaaaaaaa', "\0\0\0\0\0\0\0\x08"],
            ['aaaaaaaaa', "\0\0\0\0\0\0\x07"],
            ['aaaaaaaaaa', "\0\0\0\0\0\x06"],
            ['aaaaaaaaaaa', "\0\0\0\0\x05"],
            ['aaaaaaaaaaaa', "\0\0\0\x04"],
            ['aaaaaaaaaaaaa', "\0\0\x03"],
            ['aaaaaaaaaaaaaa', "\0\x02"],
            ['aaaaaaaaaaaaaaa', "\x01"],
            ['aaaaaaaaaaaaaaaa', "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x10"],
            ["aaaaaaaa\0\0\0\4", "\0\0\0\4"],
       ];
    }

    function badPadProvider()
    {
        return [
            ['a', "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x10"],
            ['a', "\0\0\0\0\0\0\0\0\xff\0\0\0\0\0\x10"],
            ['a', "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"],
            ['a', "\1\1\1\1\1\1\1\1\1\1\1\1\1\1\x0f"],
            ['a', "\1\1\1\1\1\1\1\1\1\1\1\1\1\1\0"],
            ['a', "\1"]
        ];
    }

    /**
     * @dataProvider goodPadProvider
     */
    function testGetPadding($message, $expected)
    {
        $scheme = new ANSIX923();
        $result = $scheme->getPadding($message);
        $this->assertSame($expected, $result);
    }

    /**
     * @dataProvider goodPadProvider
     */
    function testGetPadLen($message, $expected)
    {
        $scheme = new ANSIX923();
        $result = $scheme->getPaddingLength($message . $expected);
        $this->assertSame(16 - (strlen($message) % 16), $result);
    }

    /**
     * @expectedException \AES\Exception\InvalidPaddingException
     * @dataProvider badPadProvider
     */
    function testBadGetPadLen($message, $expected)
    {
        $scheme = new ANSIX923();
        $scheme->getPaddingLength($message . $expected);
    }
} 

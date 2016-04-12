<?php declare(strict_types = 1);

namespace AES\Test;

use AES\Mode\OCB;
use AES\Key;

class OCBTest extends \PHPUnit_Framework_TestCase
{
    private $key = '000102030405060708090a0b0c0d0e0f';

    function caseProvider()
    {
        return [
            // nonce, aad, plaintext, ciphertext, tag
            ['bbaa99887766554433221100', '', '', '', '785407bfffc8ad9edcc5520ac9111ee6'],
            ['bbaa99887766554433221101', '0001020304050607', '0001020304050607', '6820b3657b6f615a', '5725bda0d3b4eb3a257c9af1f8f03009'],
            ['bbaa99887766554433221102', '0001020304050607', '', '', '81017f8203f081277152fade694a0a00'],
            ['bbaa99887766554433221103', '', '0001020304050607', '45dd69f8f5aae724', '14054cd1f35d82760b2cd00d2f99bfa9'],
            ['bbaa99887766554433221104', '000102030405060708090a0b0c0d0e0f', '000102030405060708090a0b0c0d0e0f', '571d535b60b277188be5147170a9a22c', '3ad7a4ff3835b8c5701c1ccec8fc3358'],
            ['bbaa99887766554433221105', '000102030405060708090a0b0c0d0e0f', '', '', '8cf761b6902ef764462ad86498ca6b97'],
            ['bbaa99887766554433221106', '', '000102030405060708090a0b0c0d0e0f', '5ce88ec2e0692706a915c00aeb8b2396', 'f40e1c743f52436bdf06d8fa1eca343d'],
            ['bbaa99887766554433221107', '000102030405060708090a0b0c0d0e0f1011121314151617', '000102030405060708090a0b0c0d0e0f1011121314151617', '1ca2207308c87c010756104d8840ce1952f09673a448a122', 'c92c62241051f57356d7f3c90bb0e07f'],
            ['bbaa99887766554433221108', '000102030405060708090a0b0c0d0e0f1011121314151617', '', '', '6dc225a071fc1b9f7c69f93b0f1e10de'],
            ['bbaa99887766554433221109', '', '000102030405060708090a0b0c0d0e0f1011121314151617', '221bd0de7fa6fe993eccd769460a0af2d6cded0c395b1c3c', 'e725f32494b9f914d85c0b1eb38357ff'],
            ['bbaa9988776655443322110a', '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'bd6f6c496201c69296c11efd138a467abd3c707924b964deaffc40319af5a485', '40fbba186c5553c68ad9f592a79a4240'],
            ['bbaa9988776655443322110b', '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', '', '', 'fe80690bee8a485d11f32965bc9d2a32'],
            ['bbaa9988776655443322110c', '', '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', '2942bfc773bda23cabc6acfd9bfd5835bd300f0973792ef46040c53f1432bcdf', 'b5e1dde3bc18a5f840b52e653444d5df'],
            ['bbaa9988776655443322110d', '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627', '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627', 'd5ca91748410c1751ff8a2f618255b68a0a12e093ff454606e59f9c1d0ddc54b65e8628e568bad7a', 'ed07ba06a4a69483a7035490c5769e60'],
            ['bbaa9988776655443322110e', '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627', '', '', 'c5cd9d1850c141e358649994ee701b68'],
            ['bbaa9988776655443322110f', '', '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627', '4412923493c57d5de0d700f753cce0d1d2d95060122e9f15a5ddbfc5787e50b5cc55ee507bcb084e', '479ad363ac366b95a98ca5f3000b1479'],
        ];
    }

    /**
     * @dataProvider caseProvider
     */
    function testEncrypt($nonce, $aad, $plaintext, $ciphertext, $tag)
    {
        $key = new Key(hex2bin($this->key));
        $ocb = new OCB();

        $ctx = $ocb->init($key, hex2bin($nonce));
        $result = $ocb->encrypt($ctx, hex2bin($plaintext));
        $result .= $ocb->finalise($ctx);
        $resultTag = $ocb->tag($ctx, hex2bin($aad));

        $this->assertSame(hex2bin($ciphertext), $result);
        $this->assertSame(hex2bin($tag), $resultTag);
    }

    /**
     * @dataProvider caseProvider
     */
    function testDecrypt($nonce, $aad, $plaintext, $ciphertext, $tag)
    {
        $key = new Key(hex2bin($this->key));
        $ocb = new OCB();

        $ctx = $ocb->init($key, hex2bin($nonce));
        $result = $ocb->decrypt($ctx, hex2bin($ciphertext));
        $result .= $ocb->finalise($ctx);
        $resultTag = $ocb->tag($ctx, hex2bin($aad));

        $this->assertSame(hex2bin($plaintext), $result);
        $this->assertSame(hex2bin($tag), $resultTag);
    }

    /**
     * @dataProvider caseProvider
     */
    function testEncryptMultiMessage($nonce, $aad, $plaintext, $ciphertext, $tag)
    {
        $key = new Key(hex2bin($this->key));
        $ocb = new OCB();
        $ctx = $ocb->init($key, hex2bin($nonce));

        $result = '';
        $plain = str_split(hex2bin($plaintext), 16);
        foreach ($plain as $chunk) {
            $result .= $ocb->encrypt($ctx, $chunk);
        }
        $result .= $ocb->finalise($ctx);
        $resultTag = $ocb->tag($ctx, hex2bin($aad));

        $this->assertSame(hex2bin($ciphertext), $result);
        $this->assertSame(hex2bin($tag), $resultTag);
    }

    /**
     * @dataProvider caseProvider
     */
    function testDecryptMultiMessage($nonce, $aad, $plaintext, $ciphertext, $tag)
    {
        $key = new Key(hex2bin($this->key));
        $ocb = new OCB();
        $ctx = $ocb->init($key, hex2bin($nonce));

        $result = '';
        $cipher = str_split(hex2bin($ciphertext), 16);
        foreach ($cipher as $chunk) {
            $result .= $ocb->decrypt($ctx, $chunk);
        }
        $result .= $ocb->finalise($ctx);
        $resultTag = $ocb->tag($ctx, hex2bin($aad));

        $this->assertSame(hex2bin($plaintext), $result);
        $this->assertSame(hex2bin($tag), $resultTag);
    }
}

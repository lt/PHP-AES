AES in PHP
==========

This library contains pure PHP implementations of the AES algorithm.

The library has been optimised for speed, not for elegant looking code and requires PHP 5.4 or greater.

Block cipher implementations are in the `AES\Block` namespace. The following block ciphers are present:

 - AES128
 - AES192
 - AES256

Stream cipher implementations are in the `AES\Stream` namespace. The following stream modes are present:

 - ECB
 - CBC
 - CTR

### Usage:

```
\\ Instantiate a block cipher
$aes = new AES\Block\AES128();
$aes->setKey($key);

\\ Block operations can be performed with:
$aes->encrypt($block);
$aes->decryot($block);

\\ Stream operations can be performed with:
$ctr = new AES\Stream\CTR();
$ctr->encrypt($aes, $message, $nonce);
$ctr->decrypt($aes, $message, $nonce);
```

Remember if you are using block level encrypt/decrypt, blocks are assumed to be 16 bytes long.

Stream modes are likely not in their final state, I'm still thinking about how to make them faster without a ton of code duplication.

### TODO:
 - Implement an AES Context for proper streaming
 - Padding options (i.e. stream->finish($ctx) would pad remaining buffer and return final block)
 - Implement crappy modes just because (OFB, CFB, etc.)
 - Implement some authenticated modes
 - Stream mode tests

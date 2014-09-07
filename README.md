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

Padding implementations are in the `AES\Padding` namespace. The following padding schemes are present:

 - PKCS7
 - ANSI X.923
 - ISO/IEC 7816
 - Zero (pad with null characters)

### Usage:

```
// Instantiate a context
$ctx = new \AES\Context();

// Instantiate a block cipher
$aes = new \AES\Block\AES128();

// If you only want to perform single block operations (the same as a single block of ECB)
$aes->init($ctx, $key);

$aes->encryptBlock($ctx, $block);
$aes->decryptBlock($ctx, $block);

// If you want to stream data you'll need a seperate context for encryption and decryption (may change)
$ctr = new AES\Stream\CTR();

$ctr->init($ctxEnc, $aes, $key, $nonce);
$ctxDec = clone $ctxEnc

$ctr->encrypt($ctxEnc, $message, $final = false);
$ctr->encrypt($ctxDec, $message, $final = false);

// If the message is not a multiple of blocksize (16 bytes), the remainder is buffered.
// If you are sending the entire message at once, or when you have sent the last block of the message
// then $final must be set to true. This will apply padding (if neccessary) and return the last block
$ctr->encrypt($ctxEnc, $message, $final = false);
$ctr->encrypt($ctxDec, $message, $final = false);
```

Remember if you are using block level encrypt/decrypt, blocks are assumed to be 16 bytes long.

Stream modes are likely not in their final state, I'm still thinking about how to make them faster without a ton of code duplication.

### TODO:
 - Padding options (i.e. stream->finish($ctx) would pad remaining buffer and return final block)
 - Implement crappy modes just because (OFB, CFB, etc.)
 - Implement some authenticated modes
 - Stream mode tests

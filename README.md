AES in PHP
==========

This library contains pure PHP implementations of the AES block cipher and several modes of operation based on it.

**These are toy implementations for fun/education and come with exactly zero security guarantees.**

The underlying block cipher variation is chosen automatically based on the length of the supplied key.

 - AES-128 is used when a 16 byte key is supplied
 - AES-192 is used when a 24 byte key is supplied
 - AES-256 is used when a 32 byte key is supplied

It is the responsibility of the user to ensure that the message is properly padded when using a block mode. If the supplied message is not a multiple of 16 bytes in length an exception will be thrown.

The following block chaining modes are available:

 - ECB
 - CBC

The following stream cipher modes are available:

 - CTR
 - CFB
 - OFB

The following AEAD modes are available:

 - OCB
 - GCM

The following padding schemes are available:

 - PKCS7
 - ANSI X.923
 - ISO/IEC 7816

### Usage:

To use any mode of operation you need to create an appropriate `Context`. The context keeps track of the state of processing, allowing longer messages to be processed in multiple blocks.

Separate contexts are required for encryption and decryption.

Basic modes can be used as follows:

```
$key = new AES\Key('abcdefghijklmnop');
$nonce = 'abcdefghijklmnop';

$ctr = new AES\CTR;
$encryptionContext = $ctr->initEncryption($key, $nonce);

$ciphertext = $ctr->encrypt($encryptionContext, $plaintext0);
$ciphertext .= $ctr->encrypt($encryptionContext, $plaintext1);
```

AEAD modes are slightly more complicated.

OCB
 - AAD can be processed at any time
 - `encrypt()` and `decrypt()` will output aligned to 16-byte blocks and `finalise()` returns the final piece of ciphertext/plaintext.

GCM
 - AAD has to be processed first.
 - `encrypt()` and `decrypt()` will output the same amount as input



```
$key = new AES\Key('abcdefghijklmnop');
$nonce = 'abcdefghijkl'; // 12 byte nonce for GCM
$aad = 'Hello'

$gcm = new AES\GCM;
$encryptionContext = $gcm->initEncryption($key, $nonce);

$gcm->aad($aad);
$gcm->aad($aad);

$ciphertext = $ctr->encrypt($encryptionContext, $plaintext0);
$ciphertext .= $ctr->encrypt($encryptionContext, $plaintext1);

$gcm->finalise($context);

// $gcm->authenticate($context, $tag); // If decrypting
$tag = $gcm->tag($context);
```


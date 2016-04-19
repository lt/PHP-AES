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

All modes have one-shot `encrypt()` and `decrypt()` methods which accept different parameters depending on the mode.

Example:

```php
$key = new AES\Key('abcdefghijklmnop');
$nonce = 'abcdefghijklmnop';

$ctr = new AES\CTR;
$ciphertext = $ctr->encrypt($key, $nonce, $plaintext);
```

All modes also have streaming capabilities allowing encryption/decryption to be done in chunks.

To use any mode of operation like this an appropriate `Context` needs to be initialised first. The context keeps track of state allowing longer messages to be processed in multiple blocks.

Separate contexts are required for encryption and decryption.

Example:
```php
$key = new AES\Key('abcdefghijklmnop');
$nonce = 'abcdefghijklmnop';

$ctr = new AES\CTR;
$encryptionContext = $ctr->initEncryption($key, $nonce);

$ciphertext = $ctr->streamEncrypt($encryptionContext, $plaintext0);
$ciphertext .= $ctr->streamEncrypt($encryptionContext, $plaintext1);
```

AEAD modes are slightly more complicated.

A few caveats:
- OCB when streaming can process AAD at any time
- GCM when streaming has to process AAD first
- GCM only validates the tag prior to decryption when using the one-shot `decrypt()`. It can't do this with `streamDecrypt()` because it doesn't have all of the data yet.
- GCM has a significant initialisation overhead (time and memory) which is key dependant. If you plan to re-use the same key with different nonces you can use the `reInit()` method
- OCB and GCM one-shot `encrypt()` returns an array of `[$ciphertext, $tag]`
- OCB and GCM when streaming will output aligned to 16-byte blocks and `finalise()` returns the final piece of ciphertext/plaintext. // TODO: Fix for GCM, OCB doesn't seem possible

Example stream usage:

```php
$key = new AES\Key('abcdefghijklmnop');
$nonce = 'abcdefghijkl'; // 12 byte nonce for GCM
$aad = 'Hello'

$gcm = new AES\GCM;
$encryptionContext = $gcm->initEncryption($key, $nonce);

$gcm->aad($aad0);
$gcm->aad($aad1);

$ciphertext = $gcm->streamEncrypt($encryptionContext, $plaintext0);
$ciphertext .= $gcm->streamEncrypt($encryptionContext, $plaintext1);
$ciphertext .= $gcm->finalise($context);

// $gcm->verify($context, $tag); // If decrypting
$tag = $gcm->tag($context);
```

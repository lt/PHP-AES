AES in PHP
==========

This library contains pure PHP implementations of the AES algorithm.

The library has been optimised for speed in certain scenarios, not for elegant looking or design pattern strict code. The assumption is that under typical usage, only a single mode of operation will be used, and messages will not typically be less than 16 bytes.

The underlying block cipher variation is chosen automatically based on the length of the supplied key.

 - AES-128 is used when a 16 byte key is supplied
 - AES-192 is used when a 24 byte key is supplied
 - AES-256 is used when a 32 byte key is supplied

It is the responsibility of the user to ensure that the message is properly padded when not using a stream cipher mode. If the supplied message is not a multiple of 16 bytes in length, the trailing bytes will simply not be processed. Various padding schemes have been provided to assist.

The following block chaining modes are available:

 - ECB
 - CBC

The following stream cipher modes are available:

 - CTR

The following padding schemes are available:

 - PKCS7
 - ANSI X.923
 - ISO/IEC 7816
 - Zero (pad with null characters)

### Usage:

To use any mode of operation you need to create an appropriate `Context`, the context keeps track of the state of encryption, allowing large messages to be encrypted in multiple blocks.

Separate contexts are required for encryption and decryption, as different keys may be used for each of these operations.

```
// Instantiate a context
$ctx = new AES\Context\CTR($key, $nonce);

// Instantiate a block cipher
$ctr = new AES\Mode\CTR();

// Encrypt / decrypt a message
$ctr->encrypt($ctx, $messagePart1);

// Encrypt / decrypt more of a message
$ctr->encrypt($ctx, $messagePart2);
```

### TODO:
 - Implement crappy modes just because (OFB, CFB, etc.)
 - Implement some authenticated modes
 - Stream mode tests

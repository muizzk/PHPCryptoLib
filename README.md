# PHPCryptoLib

![Github License](https://img.shields.io/badge/License-MIT-green.svg)
[![Build Status](https://travis-ci.org/llj-vcs/PHPCryptoLib.svg?branch=master)](https://travis-ci.org/llj-vcs/PHPCryptoLib)
<!--[![codecov](https://codecov.io/gh/llj-vcs/PHPCryptoLib/branch/master/graph/badge.svg)](https://codecov.io/gh/llj-vcs/PHPCryptoLib)-->

**PHPCryptoLib is an API like library that simplifies the usage of PHP's cryptographic functions.**

*PHPCryptoLib is only tested against PHP 7.2 and 7.3!*

*This library is still in development. Support for more algorithms will be implemented!*

#### Supported algorithms so far:

- AES
- Blowfish
- Cast5
- IDEA
- Camellia
- Chacha20
- DES-EDE3
- RSA (key pair generation)
- DSA (key pair generation)

#### Example

*This is an example of an encryption and decryption with AES-256-CBC*

```php
require __DIR__.'/vendor/autoload.php';

use LLJVCS\PHPCryptoLib\openSSLAPI\openSSLAPI;

$api = new openSSLAPI();
$api->setEncoded(true); // returns the encrypted text base64 encoded
$cipher = $api->AESencrypt('Hello World!');
echo "Cipher text: ".$cipher->getData();
echo "Key: ".$cipher->getKey();
echo "IV: ".$cipher->getIv();
echo "Algorithm: ".$cipher->getAlgorithm();
echo "Encoded: ".$cipher->getEncoded();
$clear = $api->AESdecrypt($cipher->getData(), $cipher->getKey(), $cipher->getIv(), $cipher->getAlgorithm(), $cipher->getEncoded());
echo "Clear text: ".$clear->getData(); //output: Hello World!
```

Every function returns an object of type `openSSLReturn`.

As seen in the example, this object has 5 methods:

`getData(): string` returns the encrypted/decrypted string

`getKey(): string` returns the key used

`getIv(): string` returns the initialization vector used

`getAlgorithm(): string` returns the exact algorithm used

`getEncoded(): bool` returns if the output is encoded

***Note:*** *Support for normal DES will not be implemented for now since this algorithm should not be used anyway.*

Bugs, questions and suggestions please at: llj.vcs@web.de

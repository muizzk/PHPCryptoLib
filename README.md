# PHPCryptoLib

**PHPCryptoLib is an API like library that simplifies the usage of PHP's cryptographic functions.**

Example of openSSL AES 256 CBC encryption
```php
require_once __DIR__.'/vendor/autoload.php';

use LLJVCS\PHPCryptoLib\openSSLAPI\openSSLAPI;

$api = new openSSLAPI();

$api->setEncoded(true);

$cipher = $api->openSSLAESencrypt('Hello World!');

echo $cipher->getData();
```

You will get an `openSSLReturn` object with the following methods:

`getData(): string` -> returns the encrypted data.

`getKey(): string` -> returns the encryption key.

`getIv(): string` -> returns the encryption initialization vector.

`getAlgorithm(): string` -> returns the encryption algorithm.

`getEncoded(): bool` -> returns if the output is encoded (true/false)

# PHPCryptoLib

**PHPCryptoLib is an API like library that simplifies the usage of PHP's cryptographic functions.**

Example of openSSL AES 256 CBC encryption
```php
require_once __DIR__.'/vendor/autoload.php';

use LLJVCS\PHPCryptoLib\openSSLAPI\openSSLAPI;

$api = new openSSLAPI();

$cipher = $api->openSSLAESencrypt('Hello World!', 256, 'CBC', null, null, true);

echo $cipher->getData();
```

By setting the last parameter to true, the encrypted data gets ``base64_encode()`` encoded returned.

A blueprint of the function with its parameters:

``openSSLAESencrypt(string $data, int $length, string $mode, string $key, string $iv, bool $encoded)``

``$data`` -> The data you want to encrypt.

``$length`` -> The key length.

``$mode`` -> The mode of operation.

``$key`` -> The key (doesn't have to be provided)

``$iv`` -> The initialization vector (doesn't have to be provided)

``$encoded`` -> The flag if the returning data should be base64 encoded (default is false)

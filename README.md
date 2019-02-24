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

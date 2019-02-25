# PHPCryptoLib

**PHPCryptoLib is an API like library that simplifies the usage of PHP's cryptographic functions.**

Example of openSSL AES 256 CBC encryption
```php
require_once __DIR__.'/vendor/autoload.php';

use LLJVCS\PHPCryptoLib\openSSLAPI\openSSLAPI;

$api = new openSSLAPI();

$api->setEncoded(true);

$cipher = $api->openSSLAESencrypt('Hello World!', 256, 'CBC', null, null);

echo $cipher->getData();
```

<?php

require_once __DIR__.'/vendor/autoload.php';

use LLJVCS\PHPCryptoLib\openSSLAPI\openSSLAPI;

$api = new openSSLAPI();

$cipher = $api->openSSLAESencrypt('Hello World!', 'CBC', 256, null, null, true);

echo "AES: ".$cipher->getData().PHP_EOL;

$cipher = $api->openSSLBFencrypt('Hello World!', 'CBC', 448,null, null, true);

echo "Blowfish: ".$cipher->getData().PHP_EOL;

$cipher = $api->openSSLCast5encrypt('Hello World!', 'CBC', 128, null, null, true);

echo "Cast5: ".$cipher->getData().PHP_EOL;

$cipher = $api->openSSLIDEAencryption('Hello World!', 'CBC', null, null, true);

echo "IDEA: ".$cipher->getData().PHP_EOL;


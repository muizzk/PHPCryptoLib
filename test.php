<?php

require_once __DIR__.'/vendor/autoload.php';

use LLJVCS\PHPCryptoLib\openSSLAPI\openSSLAPI;

$api = new openSSLAPI();

$api->setEncoded(true);

$cipher = $api->openSSLAESencrypt('Hello World!', 'CBC', 256);

echo "AES: ".$cipher->getData().PHP_EOL;

$cipher = $api->openSSLBFencrypt('Hello World!', 'CBC', 448);

echo "Blowfish: ".$cipher->getData().PHP_EOL;

$cipher = $api->openSSLCast5encrypt('Hello World!', 'CBC', 128);

echo "Cast5: ".$cipher->getData().PHP_EOL;

$cipher = $api->openSSLIDEAencrypt('Hello World!', 'CBC');

echo "IDEA: ".$cipher->getData().PHP_EOL;


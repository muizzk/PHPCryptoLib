<?php

require_once __DIR__.'/vendor/autoload.php';

use LLJVCS\PHPCryptoLib\openSSLAPI\openSSLAPI;

$api = new openSSLAPI();

$cipher = $api->openSSLAESencrypt('Hello World!', 256, 'CBC', null, null, true);

echo $cipher->getData().PHP_EOL;

$cipher = $api->openSSLBFencrypt('Hello World!', 'CBC', null, null, true);

echo $cipher->getData();

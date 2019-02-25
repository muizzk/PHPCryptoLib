<?php

require_once __DIR__.'/vendor/autoload.php';

use LLJVCS\PHPCryptoLib\openSSLAPI\openSSLAPI;

$api = new openSSLAPI();

$api->setEncoded(true);

$cipher = $api->openSSLAESencrypt('Hello World!');

echo "AES: ".$cipher->getData().PHP_EOL;

$cipher = $api->openSSLAESdecrypt($cipher->getData(), $cipher->getKey(), $cipher->getIv(), $cipher->getAlgorithm(), $cipher->getEncoded());

echo "AES_DECRYPT: ".$cipher->getData().PHP_EOL;

$cipher = $api->openSSLBFencrypt('Hello World!');

echo "Blowfish: ".$cipher->getData().PHP_EOL;

$cipher = $api->openSSLBFdecrypt($cipher->getData(), $cipher->getKey(), $cipher->getIv(), $cipher->getAlgorithm(), $cipher->getEncoded());

echo "Blowfish_DECRYPT: ".$cipher->getData().PHP_EOL;

$cipher = $api->openSSLCast5encrypt('Hello World!');

echo "Cast5: ".$cipher->getData().PHP_EOL;

$cipher = $api->openSSLCast5decrypt($cipher->getData(), $cipher->getKey(), $cipher->getIv(), $cipher->getAlgorithm(), $cipher->getEncoded());

echo "Cast5_DECRYPT: ".$cipher->getData().PHP_EOL;

$cipher = $api->openSSLIDEAencrypt('Hello World!');

echo "IDEA: ".$cipher->getData().PHP_EOL;

$cipher = $api->openSSLIDEAdecrypt($cipher->getData(), $cipher->getKey(), $cipher->getIv(), $cipher->getAlgorithm(), $cipher->getEncoded());

echo "IDEA_DECRYPT: ".$cipher->getData().PHP_EOL;

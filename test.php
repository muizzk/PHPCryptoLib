<?php

require_once __DIR__.'/vendor/autoload.php';

use LLJVCS\PHPCryptoLib\openSSLAPI\openSSLAPI;

$api = new openSSLAPI();

$api->setEncoded(true);

$cipher = $api->AESencrypt('Hello World!');

echo "AES: ".$cipher->getData().PHP_EOL;

$cipher = $api->AESdecrypt($cipher->getData(), $cipher->getKey(), $cipher->getIv(), $cipher->getAlgorithm(), $cipher->getEncoded());

echo "AES_DECRYPT: ".$cipher->getData().PHP_EOL;

$cipher = $api->BFencrypt('Hello World!');

echo "Blowfish: ".$cipher->getData().PHP_EOL;

$cipher = $api->BFdecrypt($cipher->getData(), $cipher->getKey(), $cipher->getIv(), $cipher->getAlgorithm(), $cipher->getEncoded());

echo "Blowfish_DECRYPT: ".$cipher->getData().PHP_EOL;

$cipher = $api->Cast5encrypt('Hello World!');

echo "Cast5: ".$cipher->getData().PHP_EOL;

$cipher = $api->Cast5decrypt($cipher->getData(), $cipher->getKey(), $cipher->getIv(), $cipher->getAlgorithm(), $cipher->getEncoded());

echo "Cast5_DECRYPT: ".$cipher->getData().PHP_EOL;

$cipher = $api->IDEAencrypt('Hello World!');

echo "IDEA: ".$cipher->getData().PHP_EOL;

$cipher = $api->IDEAdecrypt($cipher->getData(), $cipher->getKey(), $cipher->getIv(), $cipher->getAlgorithm(), $cipher->getEncoded());

echo "IDEA_DECRYPT: ".$cipher->getData().PHP_EOL;

$keyPair = $api->RSAKeyAPairGeneration();

echo "Private Key: ".$keyPair->getPrivateKey().PHP_EOL;

echo "Public Key: ".$keyPair->getPublicKey().PHP_EOL;

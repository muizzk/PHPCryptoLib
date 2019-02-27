<?php

require_once __DIR__.'/vendor/autoload.php';

use LLJVCS\PHPCryptoLib\openSSLAPI\openSSLAPI;
use LucidFrame\Console\ConsoleTable;

$api = new openSSLAPI();

$api->setEncoded(true);

$cipherAES = $api->AESencrypt('Hello World!');
$cipherBF = $api->BFencrypt('Hello World!');
$cipherCast5 = $api->Cast5encrypt('Hello World!');
$cipherIDEA = $api->IDEAencrypt('Hello World!');

if (php_sapi_name() === 'cli') {
    $table = new ConsoleTable();
    $table->addHeader('Action')
        ->addHeader('Output')
        ->addRow()
        ->addColumn('Original Message')
        ->addColumn('Hello World!')
        ->addRow()
        ->addColumn('AES Encrypt')
        ->addColumn($cipherAES->getData())
        ->addRow()
        ->addColumn('Blowfish Encrypt')
        ->addColumn($cipherBF->getData())
        ->addRow()
        ->addColumn('Cast5 Encrypt')
        ->addColumn($cipherCast5->getData())
        ->addRow()
        ->addColumn('IDEA Encrypt')
        ->addColumn($cipherIDEA->getData())
        ->addRow()
        ->addColumn('AES Decrypt')
        ->addColumn($api->AESdecrypt($cipherAES->getData(), $cipherAES->getKey(), $cipherAES->getIv(), $cipherAES->getAlgorithm(), $cipherAES->getEncoded())->getData())
        ->addRow()
        ->addColumn('Blowfish Decrypt')
        ->addColumn($api->BFdecrypt($cipherBF->getData(), $cipherBF->getKey(), $cipherBF->getIv(), $cipherBF->getAlgorithm(), $cipherBF->getEncoded())->getData())
        ->addRow()
        ->addColumn('Cast5 Decrypt')
        ->addColumn($api->Cast5decrypt($cipherCast5->getData(), $cipherCast5->getKey(), $cipherCast5->getIv(), $cipherCast5->getAlgorithm(), $cipherCast5->getEncoded())->getData())
        ->addRow()
        ->addColumn('IDEA Decrypt')
        ->addColumn($api->IDEAdecrypt($cipherIDEA->getData(), $cipherIDEA->getKey(), $cipherIDEA->getIv(), $cipherIDEA->getAlgorithm(), $cipherIDEA->getEncoded())->getData())
        ->display();
}

<?php

require_once __DIR__.'/vendor/autoload.php';

use LLJVCS\PHPCryptoLib\openSSLAPI\openSSLAPI;
use LucidFrame\Console\ConsoleTable;

$api = new openSSLAPI();

$api->setEncoded(true);

$originalMessage = 'Hello World!';

$cipherAES = $api->AESencrypt($originalMessage);
$cipherBF = $api->BFencrypt($originalMessage);
$cipherCast5 = $api->Cast5encrypt($originalMessage);
$cipherIDEA = $api->IDEAencrypt($originalMessage);
$cipherCamellia = $api->Camelliaencrypt($originalMessage);
$cipherChacha20 = $api->chacha20encrypt($originalMessage);

if (php_sapi_name() === 'cli') {
    $table = new ConsoleTable();
    $table->addHeader('Action')
        ->addHeader('Output')
        ->addRow()
        ->addColumn('Original Message')
        ->addColumn($originalMessage)
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
        ->addColumn('Camellia Encrypt')
        ->addColumn($cipherCamellia->getData())
        ->addRow()
        ->addColumn('Chacha20 Encrypt')
        ->addColumn($cipherChacha20->getData())
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
        ->addRow()
        ->addColumn('Camellia Decrypt')
        ->addColumn($api->Camelliadecrypt($cipherCamellia->getData(), $cipherCamellia->getKey(), $cipherCamellia->getIv(), $cipherCamellia->getAlgorithm(), $cipherCamellia->getEncoded())->getData())
        ->addRow()
        ->addColumn('Chacha20 Decrypt')
        ->addColumn($api->chacha20decrypt($cipherChacha20->getData(), $cipherChacha20->getKey(), $cipherChacha20->getIv(), $cipherChacha20->getAlgorithm(), $cipherChacha20->getEncoded())->getData())
        ->display();
}

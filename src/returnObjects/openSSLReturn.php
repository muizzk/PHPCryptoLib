<?php

namespace LLJVCS\PHPCryptoLib\returnObjects\openSSLAESReturn;
use LLJVCS\PHPCryptoLib\Interfaces\openSSLReturn as openSSLReturnInterface;

class openSSLReturn implements openSSLReturnInterface
{

    public $data;
    public $key;
    public $iv;
    public $algorithm;

    function __construct(string $data, string $key, string $iv, string $algorithm)
    {
        $this->data = $data;
        $this->key = $key;
        $this->iv = $iv;
        $this->algorithm = $algorithm;
    }

    public function getData(): string {
        return $this->data;
    }

    public function getKey(): string {
        return $this->key;
    }

    public function getIv(): string {
        return $this->iv;
    }

    public function getAlgorithm(): string {
        return $this->algorithm;
    }

}
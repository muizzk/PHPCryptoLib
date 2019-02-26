<?php

namespace LLJVCS\PHPCryptoLib\returnObjects;
use LLJVCS\PHPCryptoLib\Interfaces\openSSLReturn as openSSLReturnInterface;

class openSSLReturn implements openSSLReturnInterface
{

    private $data;
    private $key;
    private $iv;
    private $algorithm;
    private $encoded;

    function __construct(string $data='', string $key='', string $iv='', string $algorithm='', bool $encoded=false)
    {
        $this->data = $data;
        $this->key = $key;
        $this->iv = $iv;
        $this->algorithm = $algorithm;
	    $this->encoded = $encoded;
    }

    public function setData(string $data): void
    {
        $this->data = $data;
    }

    public function getData(): string {
        return $this->data;
    }

    public function setKey(string $key): void
    {
        $this->key = $key;
    }

    public function getKey(): string {
        return $this->key;
    }

    public function setIv(string $iv): void
    {
        $this->iv = $iv;
    }

    public function getIv(): string {
        return $this->iv;
    }

    public function setAlgorithm(string $algorithm): void
    {
        $this->algorithm = $algorithm;
    }

    public function getAlgorithm(): string {
        return $this->algorithm;
    }

    public function setEncoded(bool $encoded): void
    {
        $this->encoded = $encoded;
    }

    public function getEncoded(): bool {
	    return $this->encoded;
    }

}

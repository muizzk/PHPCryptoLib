<?php

namespace LLJVCS\PHPCryptoLib\returnObjects;
use LLJVCS\PHPCryptoLib\interfaces\openSSLKeyPair as opensslKeyPairInterface;


class openSSLKeyPairReturn implements opensslKeyPairInterface
{

    private $privateKey;
    private $publicKey;
    private $keyLength;
    private $digestAlg;

    public function __construct(string $privateKey='', string $publicKey='', int $keyLength=0, string $digestAlg='')
    {
        $this->privateKey=$privateKey;
        $this->publicKey=$publicKey;
        $this->keyLength=$keyLength;
        $this->digestAlg=$digestAlg;
    }

    public function setPrivateKey(string $privateKey): void
    {
        $this->privateKey = $privateKey;
    }

    public function getPrivateKey(): string
    {
        return $this->privateKey;
    }

    public function setPublicKey(string $publicKey): void
    {
        $this->publicKey = $publicKey;
    }

    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    public function setKeyLength(int $keyLength): void
    {
        $this->keyLength = $keyLength;
    }

    public function getKeyLength(): int
    {
        return $this->keyLength;
    }

    public function setDigestAlg(string $digestAlg): void
    {
        $this->digestAlg = $digestAlg;
    }

    public function getDigestAlg(): string
    {
        return $this->digestAlg;
    }

}
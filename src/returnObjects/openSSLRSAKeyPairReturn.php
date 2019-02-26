<?php

namespace LLJVCS\PHPCryptoLib\returnObjects;
use LLJVCS\PHPCryptoLib\interfaces\opensslRSAKeyPair as opensslRSAKeyPairInterface;


class openSSLRSAKeyPairReturn implements opensslRSAKeyPairInterface
{

    private $privateKey;
    private $publicKey;
    private $keyLength;
    private $digestAlg;

    public function __construct(string $privateKey, string $publicKey, int $keyLength, string $digestAlg)
    {
        $this->privateKey=$privateKey;
        $this->publicKey=$publicKey;
        $this->keyLength=$keyLength;
        $this->digestAlg=$digestAlg;
    }

    public function getPrivateKey(): string
    {
        return $this->privateKey;
    }

    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    public function getKeyLength(): int
    {
        return $this->keyLength;
    }

    public function getDigestAlg(): string
    {
        return $this->digestAlg;
    }

}
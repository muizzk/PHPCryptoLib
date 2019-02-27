<?php

namespace LLJVCS\PHPCryptoLib\interfaces;


interface openSSLKeyPair
{

    /**
     * @param string $privateKey
     */

    public function setPrivateKey(string $privateKey): void ;

    /**
     * @return string
     */

    public function getPrivateKey(): string ;

    /**
     * @param string $publicKey
     */

    public function setPublicKey(string $publicKey): void ;

    /**
     * @return string
     */

    public function getPublicKey(): string ;

    /**
     * @param int $keyLength
     */

    public function setKeyLength(int $keyLength): void ;

    /**
     * @return int
     */

    public function getKeyLength(): int ;

    /**
     * @param string $digestAlg
     */

    public function setDigestAlg(string $digestAlg): void;

    /**
     * @return string
     */

    public function getDigestAlg(): string ;

}
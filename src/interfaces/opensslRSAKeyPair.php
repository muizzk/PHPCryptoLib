<?php

namespace LLJVCS\PHPCryptoLib\interfaces;


interface opensslRSAKeyPair
{

    /**
     * @return string
     */

    public function getPublicKey(): string ;

    /**
     * @return string
     */

    public function getPrivateKey(): string ;

    /**
     * @return int
     */

    public function getKeyLength(): int ;

    /**
     * @return string
     */

    public function getDigestAlg(): string ;

}
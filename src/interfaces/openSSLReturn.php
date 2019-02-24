<?php

namespace LLJVCS\PHPCryptoLib\Interfaces;


interface openSSLReturn
{

    /**
     * @return string
     */

    public function getData(): string ;

    /**
     * @return string
     */

    public function getKey(): string ;

    /**
     * @return string
     */

    public function getIv(): string ;

    /**
     * @return string
     */

    public function getAlgorithm(): string ;

}
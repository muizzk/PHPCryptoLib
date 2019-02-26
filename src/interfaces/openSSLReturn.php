<?php

namespace LLJVCS\PHPCryptoLib\Interfaces;


interface openSSLReturn
{

    /**
     * @param string $data
     */

    public function setData(string $data): void ;

    /**
     * @return string
     */

    public function getData(): string ;

    /**
     * @param string $key
     */

    public function setKey(string $key): void ;

    /**
     * @return string
     */

    public function getKey(): string ;

    /**
     * @param string $iv
     */

    public function setIv(string $iv): void ;

    /**
     * @return string
     */

    public function getIv(): string ;

    /**
     * @param string $algorithm
     */

    public function setAlgorithm(string $algorithm): void ;

    /**
     * @return string
     */

    public function getAlgorithm(): string ;

    /**
     * @param bool $encoded
     */

    public function setEncoded(bool $encoded): void ;
	
	/**
	 * @return bool
	 */
	 
	 public function getEncoded(): bool ;

}
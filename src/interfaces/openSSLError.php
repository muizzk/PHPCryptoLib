<?php

namespace LLJVCS\PHPCryptoLib\interfaces;


interface openSSLError
{

    /**
     * @param string $message
     */

    public function setMessage(string $message): void ;

    /**
     * @return string
     */

    public function getMessage(): string ;

    /**
     * @param int $code
     */

    public function setCode(int $code): void ;

    /**
     * @return int
     */

    public function getCode(): int ;

    /**
     * @param string $trace
     */

    public function setStringTrace(string $trace): void ;

    /**
     * @return string
     */

    public function getStringTrace(): string ;

}
<?php

namespace LLJVCS\PHPCryptoLib\returnObjects;
use LLJVCS\PHPCryptoLib\interfaces\openSSLError as openSSLErrorInterface;


class openSSLError implements openSSLErrorInterface
{

    private $message;
    private $code;
    private $stringTrace;

    public function __construct(string $message='', int $code=0, string $stringTrace='')
    {
        $this->message = $message;
        $this->code = $code;
        $this->stringTrace = $stringTrace;
    }

    public function setMessage(string $message): void
    {
        $this->message = $message;
    }

    public function getMessage(): string
    {
        return $this->message;
    }

    public function setCode(int $code): void
    {
        $this->code = $code;
    }

    public function getCode(): int
    {
        return $this->code;
    }

    public function setStringTrace(string $trace): void
    {
        $this->stringTrace = $trace;
    }

    public function getStringTrace(): string
    {
        return $this->stringTrace;
    }

}
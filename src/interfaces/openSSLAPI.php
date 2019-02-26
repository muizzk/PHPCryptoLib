<?php

namespace LLJVCS\PHPCryptoLib\Interfaces;

interface openSSLAPI
{

    /**
     * @param int $length
     * @return string
     */

    public function generateKey(int $length): string ;

    /**
     * @param string $algorithm
     * @return string
     */

    public function generateIv(string $algorithm): string ;

    /**
     * @param $data
     * @param string $mode
     * @param int $length
     * @param string|null $key
     * @param string|null $iv
     * @return object
     */

    public function AESencrypt($data, string $mode='CBC', int $length=256, string $key=null, string $iv=null): object ;

    /**
     * @param string $data
     * @param string $key
     * @param string $iv
     * @param string $algorithm
     * @param bool $encoded
     * @return object
     */

    public function AESdecrypt(string $data, string $key, string $iv, string $algorithm, bool $encoded): object ;

    /**
     * @param $data
     * @param string $mode
     * @param int $length
     * @param string|null $key
     * @param string|null $iv
     * @return object
     */

    public function BFencrypt($data, string $mode='CBC', int $length=448, string $key=null, string $iv=null): object ;

    /**
     * @param string $data
     * @param string $key
     * @param string $iv
     * @param string $algorithm
     * @param bool $encoded
     * @return object
     */

    public function BFdecrypt(string $data, string $key, string $iv, string $algorithm, bool $encoded): object ;

    /**
     * @param $data
     * @param string $mode
     * @param int $length
     * @param string|null $key
     * @param string|null $iv
     * @return object
     */

    public function Cast5encrypt($data, string $mode='CBC', int $length=128, string $key=null, string $iv=null): object ;

    /**
     * @param string $data
     * @param string $key
     * @param string $iv
     * @param string $algorithm
     * @param bool $encoded
     * @return object
     */

    public function Cast5decrypt(string $data, string $key, string $iv, string $algorithm, bool $encoded): object ;

    /**
     * @param $data
     * @param string $mode
     * @param string|null $key
     * @param string|null $iv
     * @return object
     */

    public function IDEAencrypt($data, string $mode='CBC', string $key=null, string $iv=null): object ;

    /**
     * @param string $data
     * @param string $key
     * @param string $iv
     * @param string $algorithm
     * @param bool $encoded
     * @return object
     */

    public function IDEAdecrypt(string $data, string $key, string $iv, string $algorithm, bool $encoded): object ;

    /**
     * @param string $digestAlg
     * @param int $keyLength
     * @return object
     */

    public function RSAKeyAPairGeneration(string $digestAlg="sha512", int $keyLength=4096): object ;

}
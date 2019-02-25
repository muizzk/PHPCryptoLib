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

    public function openSSLAESencrypt($data, string $mode='CBC', int $length=256, string $key=null, string $iv=null): object ;

    /**
     * @param string $data
     * @param string $key
     * @param string $iv
     * @param string $algorithm
     * @return object
     */

    public function openSSLAESdecrypt(string $data, string $key, string $iv, string $algorithm): object ;

    /**
     * @param $data
     * @param string $mode
     * @param int $length
     * @param string|null $key
     * @param string|null $iv
     * @return object
     */

    public function openSSLBFencrypt($data, string $mode='CBC', int $length=448, string $key=null, string $iv=null): object ;

    /**
     * @param string $data
     * @param string $key
     * @param string $iv
     * @param string $algorithm
     * @return object
     */

    public function openSSLBFdecrypt(string $data, string $key, string $iv, string $algorithm): object ;

    /**
     * @param $data
     * @param string $mode
     * @param int $length
     * @param string|null $key
     * @param string|null $iv
     * @return object
     */

    public function openSSLCast5encrypt($data, string $mode='CBC', int $length=128, string $key=null, string $iv=null): object ;

    /**
     * @param string $data
     * @param string $key
     * @param string $iv
     * @param string $algorithm
     * @return object
     */

    public function openSSLCast5decrypt(string $data, string $key, string $iv, string $algorithm): object ;

    /**
     * @param $data
     * @param string $mode
     * @param string|null $key
     * @param string|null $iv
     * @return object
     */

    public function openSSLIDEAencrypt($data, string $mode='CBC', string $key=null, string $iv=null): object ;

    /**
     * @param string $data
     * @param string $key
     * @param string $iv
     * @param string $algorithm
     * @return object
     */

    public function openSSLIDEAdecrypt(string $data, string $key, string $iv, string $algorithm): object ;

}
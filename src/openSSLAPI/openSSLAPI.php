<?php

namespace LLJVCS\PHPCryptoLib\openSSLAPI;
use LLJVCS\PHPCryptoLib\PHPCryptoAPIException;
use LLJVCS\PHPCryptoLib\returnObjects\openSSLAESReturn\openSSLReturn;

class openSSLAPI
{

    /**
     * @param int $length
     * @return string
     */

    public function generateKey(int $length): string {
        return openssl_random_pseudo_bytes($length/8);
    }

    /**
     * @param string $data
     * @param int $length
     * @param string $mode
     * @param string|null $key
     * @param string|null $iv
     * @param bool $encode
     * @return object
     */
    public function openSSLAESencrypt(string $data, int $length, string $mode, string $key=null, string $iv=null, bool $encode=false): object {
        try {
            $algorithm = "AES-" . (string)$length . "-" . strtoupper($mode);
            if (!in_array($algorithm, openssl_get_cipher_methods())) {
                throw new PHPCryptoAPIException('Unknown algorithm "' . $algorithm . '"');
            }
            if (!$key) {
                $key = $this->generateKey($length);
            }
            if (!$iv) {
                $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($algorithm));
            }
            if (!$cipher = openssl_encrypt($data, $algorithm, $key, $options=OPENSSL_RAW_DATA, $iv)) {
                echo "An error occurred in PHPCryptoLib! -> ".openssl_error_string();
                die;
            }
            if ($encode) {
                $cipher = base64_encode($cipher);
            }
            return new openSSLReturn($cipher, $key, $iv, $algorithm);
        } catch (PHPCryptoAPIException $PHPCryptoAPIException) {
            echo "An error occurred in PHPCryptoLib! -> ".$PHPCryptoAPIException->getMessage();
            die;
        }
    }

    /**
     * @param string $data
     * @param string $mode
     * @param string|null $key
     * @param string|null $iv
     * @param bool|false $encoded
     * @return object
     */

    public function openSSLBFencrypt(string $data, string $mode, string $key=null, string $iv=null, bool $encoded=false): object {
        try {
            $length = 448;
            $algorithm = "BF-".strtoupper($mode);
            if (!in_array($algorithm, openssl_get_cipher_methods())) {
                throw new PHPCryptoAPIException('Unknown algorithm "' . $algorithm . '"');
            }
            if (!$key) {
                $key = $this->generateKey($length);
            }
            if (!$iv) {
                $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($algorithm));
            }
            if (!$cipher = openssl_encrypt($data, $algorithm, $key, $options=OPENSSL_RAW_DATA, $iv)) {
                echo "An error occurred in PHPCryptoLib! -> ".openssl_error_string();
                die;
            }
            if ($encoded) {
                $cipher = base64_encode($cipher);
            }
            return new openSSLReturn($cipher, $key, $iv, $algorithm);
        } catch (PHPCryptoAPIException $PHPCryptoAPIException) {
            echo "An error occurred in PHPCryptoLib! -> ".$PHPCryptoAPIException->getMessage();
            die;
        }
    }

}
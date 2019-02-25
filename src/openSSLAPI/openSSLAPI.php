<?php

namespace LLJVCS\PHPCryptoLib\openSSLAPI;
use LLJVCS\PHPCryptoLib\PHPCryptoAPIException;
use LLJVCS\PHPCryptoLib\Interfaces\openSSLAPI as openSSLAPIInterface;
use LLJVCS\PHPCryptoLib\returnObjects\openSSLAESReturn\openSSLReturn;

class openSSLAPI implements openSSLAPIInterface
{
    
    private $encoded;

    /**
     * openSSLAPI constructor.
     */

    public function __construct() {
        try {
            if (!$this->checkopenSSLenabled()) {
                throw new PHPCryptoAPIException();
            }
            $this->encoded = false;
        } catch (PHPCryptoAPIException $PHPCryptoAPIException) {
            die('openSSL extension is not enabled!');
        }
    }

    /**
     * @return bool
     */

    private function checkopenSSLenabled(): bool {
        if (!extension_loaded('openssl')) {
            return false;
        }
        return true;
    }

    /**
     * @return bool
     */
    
    public function getEncoded(): bool {
        return $this->encoded;
    }

    /**
     * @param bool $encoded
     */
    
    public function setEncoded(bool $encoded): void {
        $this->encoded = $encoded;
    }

    /**
     * @param int $length
     * @return string
     */

    public function generateKey(int $length): string {
        return openssl_random_pseudo_bytes($length/8);
    }

    /**
     * @param string $algorithm
     * @return string
     */

    public function generateIv(string $algorithm): string {
        return openssl_random_pseudo_bytes(openssl_cipher_iv_length($algorithm));
    }

    /**
     * @param string $data
     * @param int $length
     * @param string $mode
     * @param string|null $key
     * @param string|null $iv
     * @return object
     */
    public function openSSLAESencrypt($data, string $mode='CBC', int $length=256, string $key=null, string $iv=null): object {
        try {
            $algorithm = "AES-" . (string)$length . "-" . strtoupper($mode);
            if (!in_array($algorithm, openssl_get_cipher_methods())) {
                throw new PHPCryptoAPIException('Unknown algorithm "' . $algorithm . '"');
            }
            if (!$key) {
                $key = $this->generateKey($length);
            }
            if (!$iv) {
                $iv = $this->generateIv($algorithm);
            }
            if (!$cipher = openssl_encrypt($data, $algorithm, $key, $options=OPENSSL_RAW_DATA, $iv)) {
                throw new PHPCryptoAPIException(openssl_error_string());
            }
            if ($this->encoded) {
                $cipher = base64_encode($cipher);
            }
            return new openSSLReturn($cipher, $key, $iv, $algorithm, $this->encoded);
        } catch (PHPCryptoAPIException $PHPCryptoAPIException) {
            die("An error occurred in PHPCryptoLib! -> ".$PHPCryptoAPIException->getMessage());
        }
    }

    /**
     * @param string $data
     * @param string $key
     * @param string $iv
     * @param string $algorithm
     * @param bool $encoded
     * @return object
     */

    public function openSSLAESdecrypt(string $data, string $key, string $iv, string $algorithm, bool $encoded): object {
        try {
            if ($key === '' || ctype_space($key)) {
                throw new PHPCryptoAPIException('Key can\'t be empty or whitespaces!');
            }
            if (!in_array(strlen($key)*8, array(128, 192, 256))) {
                throw new PHPCryptoAPIException('Invalid Key Size '.(string)strlen($key));
            }
            if ($encoded) {
                $data = base64_decode($data);
            }
            if (!$clear = openssl_decrypt($data, $algorithm, $key, $options=OPENSSL_RAW_DATA, $iv)) {
                throw new PHPCryptoAPIException(openssl_error_string());
            }
            return new openSSLReturn($clear, $key, $iv, $algorithm, $this->encoded);
        } catch (PHPCryptoAPIException $PHPCryptoAPIException) {
            die("An error occurred in PHPCryptoLib! -> ".$PHPCryptoAPIException->getMessage());
        }
    }

    /**
     * @param string $data
     * @param string $mode
     * @param int $length
     * @param string|null $key
     * @param string|null $iv
     * @return object
     */

    public function openSSLBFencrypt($data, string $mode='CBC', int $length=448, string $key=null, string $iv=null): object {
        try {
            if ($length < 32 || $length > 448) {
                throw new PHPCryptoAPIException('Invalid Key Size '.(string)$length);
            }
            $algorithm = "BF-".strtoupper($mode);
            if (!in_array($algorithm, openssl_get_cipher_methods())) {
                throw new PHPCryptoAPIException('Unknown algorithm "' . $algorithm . '"');
            }
            if (!$key) {
                $key = $this->generateKey($length);
            }
            if (!$iv) {
                $iv = $this->generateIv($algorithm);
            }
            if (!$cipher = openssl_encrypt($data, $algorithm, $key, $options=OPENSSL_RAW_DATA, $iv)) {
                throw new PHPCryptoAPIException(openssl_error_string());
            }
            if ($this->encoded) {
                $cipher = base64_encode($cipher);
            }
            return new openSSLReturn($cipher, $key, $iv, $algorithm, $this->encoded);
        } catch (PHPCryptoAPIException $PHPCryptoAPIException) {
            die("An error occurred in PHPCryptoLib! -> ".$PHPCryptoAPIException->getMessage());
        }
    }

    /**
     * @param string $data
     * @param string $key
     * @param string $iv
     * @param string $algorithm
     * @param bool $encoded
     * @return object
     */

    public function openSSLBFdecrypt(string $data, string $key, string $iv, string $algorithm, bool $encoded): object {
        try {
            if ($key === '' || ctype_space($key)) {
                throw new PHPCryptoAPIException('Key can\'t be empty or whitespaces!');
            }
            $length = strlen($key)*8;
            if ($length < 32 || $length > 448) {
                throw new PHPCryptoAPIException('Invalid Key Size '.(string)strlen($key));
            }
            if ($encoded) {
                $data = base64_decode($data);
            }
            if (!$clear = openssl_decrypt($data, $algorithm, $key, $options=OPENSSL_RAW_DATA, $iv)) {
                throw new PHPCryptoAPIException(openssl_error_string());
            }
            return new openSSLReturn($clear, $key, $iv, $algorithm, $this->encoded);
        } catch (PHPCryptoAPIException $PHPCryptoAPIException) {
            die("An error occurred in PHPCryptoLib! -> ".$PHPCryptoAPIException->getMessage());
        }
    }

    /**
     * @param string $data
     * @param string $mode
     * @param int $length
     * @param string|null $key
     * @param string|null $iv
     * @return object
     */

    public function openSSLCast5encrypt($data, string $mode='CBC', int $length=128, string $key=null, string $iv=null): object {
        try {
            $algorithm = 'CAST5-'.strtoupper($mode);
            if (!in_array($algorithm, openssl_get_cipher_methods())) {
                throw new PHPCryptoAPIException('Unknown algorithm "' . $algorithm . '"');
            }
            if ($length < 40 || $length > 128) {
                throw new PHPCryptoAPIException('Invalid Key Size '.(string)$length);
            }
            if (!$key) {
                $key = $this->generateKey($length);
            }
            if (!$iv) {
                $iv = $this->generateIv($algorithm);
            }
            if (!$cipher = openssl_encrypt($data, $algorithm, $key, $options=OPENSSL_RAW_DATA, $iv)) {
                throw new PHPCryptoAPIException(openssl_error_string());
            }
            if ($this->encoded) {
                $cipher = base64_encode($cipher);
            }
            return new openSSLReturn($cipher, $key, $iv, $algorithm, $this->encoded);
        } catch (PHPCryptoAPIException $PHPCryptoAPIException) {
            die("An error occurred in PHPCryptoLib! -> ".$PHPCryptoAPIException->getMessage());
        }
    }

    /**
     * @param string $data
     * @param string $key
     * @param string $iv
     * @param string $algorithm
     * @param bool $encoded
     * @return object
     */

    public function openSSLCast5decrypt(string $data, string $key, string $iv, string $algorithm, bool $encoded): object {
        try {
            if ($key === '' || ctype_space($key)) {
                throw new PHPCryptoAPIException('Key can\'t be empty or whitespaces!');
            }
            $length = strlen($key)*8;
            if ($length < 40 || $length > 128) {
                throw new PHPCryptoAPIException('Invalid Key Size '.(string)strlen($key));
            }
            if ($encoded) {
                $data = base64_decode($data);
            }
            if (!$clear = openssl_decrypt($data, $algorithm, $key, $options=OPENSSL_RAW_DATA, $iv)) {
                throw new PHPCryptoAPIException(openssl_error_string());
            }
            return new openSSLReturn($clear, $key, $iv, $algorithm, $this->encoded);
        } catch (PHPCryptoAPIException $PHPCryptoAPIException) {
            die("An error occurred in PHPCryptoLib! -> ".$PHPCryptoAPIException->getMessage());
        }
    }

    /**
     * @param string $data
     * @param string $mode
     * @param string|null $key
     * @param string|null $iv
     * @return object
     */

    public function openSSLIDEAencrypt($data, string $mode='CBC', string $key=null, string $iv=null): object {
        try {
            $length = 128;
            $algorithm = 'IDEA-'.strtoupper($mode);
            if (!in_array($algorithm, openssl_get_cipher_methods())) {
                throw new PHPCryptoAPIException('Unknown algorithm "' . $algorithm . '"');
            }
            if (!$key) {
                $key = $this->generateKey($length);
            }
            if (!$iv) {
                $iv = $this->generateIv($algorithm);
            }
            if (!$cipher = openssl_encrypt($data, $algorithm, $key, $options=OPENSSL_RAW_DATA, $iv)) {
                throw new PHPCryptoAPIException(openssl_error_string());
            }
            if ($this->encoded) {
                $cipher = base64_encode($cipher);
            }
            return new openSSLReturn($cipher, $key, $iv, $algorithm, $this->encoded);
        } catch (PHPCryptoAPIException $PHPCryptoAPIException) {
            die("An error occurred in PHPCryptoLib! -> ".$PHPCryptoAPIException->getMessage());
        }
    }

    /**
     * @param string $data
     * @param string $key
     * @param string $iv
     * @param string $algorithm
     * @param bool $encoded
     * @return object
     */

    public function openSSLIDEAdecrypt(string $data, string $key, string $iv, string $algorithm, bool $encoded): object {
        try {
            if ($key === '' || ctype_space($key)) {
                throw new PHPCryptoAPIException('Key can\'t be empty or whitespace!');
            }
            if (strlen($key)*8 !== 128) {
                throw new PHPCryptoAPIException('Invalid Key Size '.(string)strlen($key));
            }
            if ($encoded) {
                $data = base64_decode($data);
            }
            if (!$clear = openssl_decrypt($data, $algorithm, $key, $options=OPENSSL_RAW_DATA, $iv)) {
                throw new PHPCryptoAPIException(openssl_error_string());
            }
            return new openSSLReturn($clear, $key, $iv, $algorithm, $this->encoded);
        } catch (PHPCryptoAPIException $PHPCryptoAPIException) {
            die("An error occurred in PHPCryptoLib! -> ".$PHPCryptoAPIException->getMessage());
        }
    }

}
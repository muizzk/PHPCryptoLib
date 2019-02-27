<?php

namespace LLJVCS\PHPCryptoLib\openSSLAPI;
use LLJVCS\PHPCryptoLib\PHPCryptoAPIException;
use LLJVCS\PHPCryptoLib\Interfaces\openSSLAPI as openSSLAPIInterface;
use LLJVCS\PHPCryptoLib\returnObjects\openSSLKeyPairReturn;
use LLJVCS\PHPCryptoLib\returnObjects\openSSLReturn;
use LLJVCS\PHPCryptoLib\returnObjects\openSSLRSAKeyPairReturn;

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
    public function AESencrypt($data, string $mode='CBC', int $length=256, string $key=null, string $iv=null): object {
        try {
            $return = new openSSLReturn();
            $algorithm = "AES-" . (string)$length . "-" . strtoupper($mode);
            if (!in_array($algorithm, openssl_get_cipher_methods())) {
                throw new PHPCryptoAPIException('Unknown algorithm "' . $algorithm . '"');
            }
            $return->setAlgorithm($algorithm);
            if (!$key) {
                $key = $this->generateKey($length);
            }
            $return->setKey($key);
            if (!$iv) {
                $iv = $this->generateIv($algorithm);
            }
            $return->setIv($iv);
            if (!$cipher = openssl_encrypt($data, $algorithm, $key, $options=OPENSSL_RAW_DATA, $iv)) {
                throw new PHPCryptoAPIException(openssl_error_string());
            }
            if ($this->encoded) {
                $cipher = base64_encode($cipher);
            }
            $return->setEncoded($this->encoded);
            $return->setData($cipher);
            return $return;
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

    public function AESdecrypt(string $data, string $key, string $iv, string $algorithm, bool $encoded): object {
        try {
            $return = new openSSLReturn();
            if ($key === '' || ctype_space($key)) {
                throw new PHPCryptoAPIException('Key can\'t be empty or whitespaces!');
            }
            $return->setKey($key);
            $return->setIv($iv);
            $return->setAlgorithm($algorithm);
            $return->setEncoded(false);
            if (!in_array(strlen($key)*8, array(128, 192, 256))) {
                throw new PHPCryptoAPIException('Invalid Key Size '.(string)strlen($key));
            }
            if ($encoded) {
                $data = base64_decode($data);
            }
            if (!$clear = openssl_decrypt($data, $algorithm, $key, $options=OPENSSL_RAW_DATA, $iv)) {
                throw new PHPCryptoAPIException(openssl_error_string());
            }
            $return->setData($clear);
            return $return;
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

    public function BFencrypt($data, string $mode='CBC', int $length=448, string $key=null, string $iv=null): object {
        try {
            $return = new openSSLReturn();
            $return->setEncoded($this->encoded);
            if ($length < 32 || $length > 448) {
                throw new PHPCryptoAPIException('Invalid Key Size '.(string)$length);
            }
            $algorithm = "BF-".strtoupper($mode);
            if (!in_array($algorithm, openssl_get_cipher_methods())) {
                throw new PHPCryptoAPIException('Unknown algorithm "' . $algorithm . '"');
            }
            $return->setAlgorithm($algorithm);
            if (!$key) {
                $key = $this->generateKey($length);
            }
            $return->setKey($key);
            if (!$iv) {
                $iv = $this->generateIv($algorithm);
            }
            $return->setIv($iv);
            if (!$cipher = openssl_encrypt($data, $algorithm, $key, $options=OPENSSL_RAW_DATA, $iv)) {
                throw new PHPCryptoAPIException(openssl_error_string());
            }
            if ($this->encoded) {
                $cipher = base64_encode($cipher);
            }
            $return->setData($cipher);
            return $return;
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

    public function BFdecrypt(string $data, string $key, string $iv, string $algorithm, bool $encoded): object {
        try {
            $return = new openSSLReturn();
            if ($key === '' || ctype_space($key)) {
                throw new PHPCryptoAPIException('Key can\'t be empty or whitespaces!');
            }
            $length = strlen($key)*8;
            if ($length < 32 || $length > 448) {
                throw new PHPCryptoAPIException('Invalid Key Size '.(string)strlen($key));
            }
            $return->setKey($key);
            $return->setIv($iv);
            $return->setAlgorithm($algorithm);
            $return->setEncoded(false);
            if ($encoded) {
                $data = base64_decode($data);
            }
            if (!$clear = openssl_decrypt($data, $algorithm, $key, $options=OPENSSL_RAW_DATA, $iv)) {
                throw new PHPCryptoAPIException(openssl_error_string());
            }
            $return->setData($clear);
            return $return;
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

    public function Cast5encrypt($data, string $mode='CBC', int $length=128, string $key=null, string $iv=null): object {
        try {
            $return = new openSSLReturn();
            $return->setEncoded($this->encoded);
            $algorithm = 'CAST5-'.strtoupper($mode);
            if (!in_array($algorithm, openssl_get_cipher_methods())) {
                throw new PHPCryptoAPIException('Unknown algorithm "' . $algorithm . '"');
            }
            $return->setAlgorithm($algorithm);
            if ($length < 40 || $length > 128) {
                throw new PHPCryptoAPIException('Invalid Key Size '.(string)$length);
            }
            if (!$key) {
                $key = $this->generateKey($length);
            }
            $return->setKey($key);
            if (!$iv) {
                $iv = $this->generateIv($algorithm);
            }
            $return->setIv($iv);
            if (!$cipher = openssl_encrypt($data, $algorithm, $key, $options=OPENSSL_RAW_DATA, $iv)) {
                throw new PHPCryptoAPIException(openssl_error_string());
            }
            if ($this->encoded) {
                $cipher = base64_encode($cipher);
            }
            $return->setData($cipher);
            return $return;
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

    public function Cast5decrypt(string $data, string $key, string $iv, string $algorithm, bool $encoded): object {
        try {
            $return = new openSSLReturn();
            $return->setEncoded(false);
            $return->setAlgorithm($algorithm);
            if ($key === '' || ctype_space($key)) {
                throw new PHPCryptoAPIException('Key can\'t be empty or whitespaces!');
            }
            $length = strlen($key)*8;
            if ($length < 40 || $length > 128) {
                throw new PHPCryptoAPIException('Invalid Key Size '.(string)strlen($key));
            }
            $return->setKey($key);
            $return->setIv($iv);
            if ($encoded) {
                $data = base64_decode($data);
            }
            if (!$clear = openssl_decrypt($data, $algorithm, $key, $options=OPENSSL_RAW_DATA, $iv)) {
                throw new PHPCryptoAPIException(openssl_error_string());
            }
            $return->setData($clear);
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

    public function IDEAencrypt($data, string $mode='CBC', string $key=null, string $iv=null): object {
        try {
            $return = new openSSLReturn();
            $return->setEncoded($this->encoded);
            $length = 128;
            $algorithm = 'IDEA-'.strtoupper($mode);
            if (!in_array($algorithm, openssl_get_cipher_methods())) {
                throw new PHPCryptoAPIException('Unknown algorithm "' . $algorithm . '"');
            }
            $return->setAlgorithm($algorithm);
            if (!$key) {
                $key = $this->generateKey($length);
            }
            $return->setKey($key);
            if (!$iv) {
                $iv = $this->generateIv($algorithm);
            }
            $return->setIv($iv);
            if (!$cipher = openssl_encrypt($data, $algorithm, $key, $options=OPENSSL_RAW_DATA, $iv)) {
                throw new PHPCryptoAPIException(openssl_error_string());
            }
            if ($this->encoded) {
                $cipher = base64_encode($cipher);
            }
            $return->setData($cipher);
            return $return;
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

    public function IDEAdecrypt(string $data, string $key, string $iv, string $algorithm, bool $encoded): object {
        try {
            $return = new openSSLReturn();
            $return->setEncoded(false);
            if ($key === '' || ctype_space($key)) {
                throw new PHPCryptoAPIException('Key can\'t be empty or whitespace!');
            }
            if (strlen($key)*8 !== 128) {
                throw new PHPCryptoAPIException('Invalid Key Size '.(string)strlen($key));
            }
            $return->setKey($key);
            $return->setIv($iv);
            $return->setAlgorithm($algorithm);
            if ($encoded) {
                $data = base64_decode($data);
            }
            if (!$clear = openssl_decrypt($data, $algorithm, $key, $options=OPENSSL_RAW_DATA, $iv)) {
                throw new PHPCryptoAPIException(openssl_error_string());
            }
            $return->setData($clear);
            return $return;
        } catch (PHPCryptoAPIException $PHPCryptoAPIException) {
            die("An error occurred in PHPCryptoLib! -> ".$PHPCryptoAPIException->getMessage());
        }
    }

    /**
     * @param string $digestAlg
     * @param int $keyLength
     * @return object
     */

    public function RSAKeyPairGeneration(string $digestAlg = "sha512", int $keyLength = 4096): object {
        try {
            $return = new openSSLKeyPairReturn();
            if (!in_array($keyLength, array(1024, 2048, 4096))) {
                throw new PHPCryptoAPIException('Invalid Key Size '.(string)$keyLength);
            }
            $return->setKeyLength($keyLength);
            $config = array(
                "digest_alg" => $digestAlg,
                "private_key_bits" => $keyLength,
                "private_key_type" => OPENSSL_KEYTYPE_RSA
            );
            if (!$res = openssl_pkey_new($config)) {
                throw new PHPCryptoAPIException(openssl_error_string());
            }
            $return->setDigestAlg($digestAlg);
            openssl_pkey_export($res, $privateKey);
            $return->setPrivateKey($privateKey);
            $publicKey = openssl_pkey_get_details($res);
            $publicKey = $publicKey["key"];
            $return->setPublicKey($publicKey);
            return $return;
        } catch (PHPCryptoAPIException $PHPCryptoAPIException) {
            die("An error occurred in PHPCryptoLib! -> ".$PHPCryptoAPIException->getMessage());
        }
    }

    public function DSAKeyPairGeneration(string $digestAlg = "sha512", int $keyLength = 2048): object {
        try {
            $return = new openSSLKeyPairReturn();
            if (!in_array($keyLength, array(1024, 2048, 4096))) {
                throw new PHPCryptoAPIException('Invalid Key Size '.(string)$keyLength);
            }
            $return->setKeyLength($keyLength);
            $config = array(
                "digest_alg" => $digestAlg,
                "private_key_bits" => $keyLength,
                "private_key_type" => OPENSSL_KEYTYPE_DSA
            );
            if (!$res = openssl_pkey_new($config)) {
                throw new PHPCryptoAPIException(openssl_error_string());
            }
            $return->setDigestAlg($digestAlg);
            openssl_pkey_export($res, $privateKey);
            $return->setPrivateKey($privateKey);
            $publicKey = openssl_pkey_get_details($res);
            $publicKey = $publicKey["key"];
            $return->setPublicKey($publicKey);
            return $return;
        } catch (PHPCryptoAPIException $PHPCryptoAPIException) {
            die("An error occurred in PHPCryptoLib! -> ".$PHPCryptoAPIException->getMessage());
        }
    }

}
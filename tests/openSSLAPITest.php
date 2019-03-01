<?php
declare(strict_types=1);

use LLJVCS\PHPCryptoLib\PHPCryptoAPIException;
use LLJVCS\PHPCryptoLib\openSSLAPI\openSSLAPI;
use LLJVCS\PHPCryptoLib\returnObjects\openSSLKeyPairReturn;
use LLJVCS\PHPCryptoLib\returnObjects\openSSLReturn;
use PHPUnit\Framework\TestCase;

final class openSSLAPITest extends TestCase
{

    private $api;
    private $originalMessage;
    private $aesEncryptObject;
    private $bfEncryptObject;
    private $cast5EncryptObject;
    private $ideaEncryptObject;
    private $camelliaEncryptObject;
    private $chacha20EncryptObject;
    private $rsaKeyPairGeneration;
    private $dsaKeyPairGeneration;
    private $aesDecryptObject;
    private $bfDecryptObject;
    private $cast5DecryptObject;
    private $ideaDecryptObject;
    private $camelliaDecryptObject;
    private $chacha20DecryptObject;

    public function __construct(?string $name = null, array $data = [], string $dataName = '')
    {
        parent::__construct($name, $data, $dataName);
        $this->api = new openSSLAPI();
        $this->originalMessage = 'Hello World!';
        $this->aesEncryptObject = $this->api->AESencrypt($this->originalMessage);
        $this->bfEncryptObject = $this->api->BFencrypt($this->originalMessage);
        $this->cast5EncryptObject = $this->api->Cast5encrypt($this->originalMessage);
        $this->ideaEncryptObject = $this->api->IDEAencrypt($this->originalMessage);
        $this->camelliaEncryptObject = $this->api->Camelliaencrypt($this->originalMessage);
        $this->chacha20EncryptObject = $this->api->cachacha20encrypt($this->originalMessage);
        $this->rsaKeyPairGeneration = $this->api->RSAKeyPairGeneration();
        $this->dsaKeyPairGeneration = $this->api->DSAKeyPairGeneration();
        $this->aesDecryptObject = $this->api->AESdecrypt($this->aesEncryptObject->getData(), $this->aesEncryptObject->getKey(), $this->aesEncryptObject->getIv(), $this->aesEncryptObject->getAlgorithm(), $this->aesEncryptObject->getEncoded());
        $this->bfDecryptObject = $this->api->BFdecrypt($this->bfEncryptObject->getData(), $this->bfEncryptObject->getKey(), $this->bfEncryptObject->getIv(), $this->bfEncryptObject->getAlgorithm(), $this->bfEncryptObject->getEncoded());
        $this->cast5DecryptObject = $this->api->Cast5decrypt($this->cast5EncryptObject->getData(), $this->cast5EncryptObject->getKey(), $this->cast5EncryptObject->getIv(), $this->cast5EncryptObject->getAlgorithm(), $this->cast5EncryptObject->getEncoded());
        $this->ideaDecryptObject = $this->api->IDEAdecrypt($this->ideaEncryptObject->getData(), $this->ideaEncryptObject->getKey(), $this->ideaEncryptObject->getIv(), $this->ideaEncryptObject->getAlgorithm(), $this->ideaEncryptObject->getEncoded());
        $this->camelliaDecryptObject = $this->api->Camelliadecrypt($this->camelliaEncryptObject->getData(), $this->camelliaEncryptObject->getKey(), $this->camelliaEncryptObject->getIv(), $this->camelliaEncryptObject->getAlgorithm(), $this->camelliaEncryptObject->getEncoded());
        $this->chacha20DecryptObject = $this->api->chacha20decrypt($this->camelliaEncryptObject->getData(), $this->camelliaEncryptObject->getKey(), $this->camelliaEncryptObject->getIv(), $this->camelliaEncryptObject->getAlgorithm(), $this->camelliaEncryptObject->getEncoded());
    }

    public function testEncodedTrue(): void {
        $this->api->setEncoded(true);
        $this->assertTrue($this->api->getEncoded());
    }

    public function testEncodedFalse(): void {
        $this->api->setEncoded(false);
        $this->assertFalse($this->api->getEncoded());
    }

    public function testGenerateKeyType(): void {
        $this->assertIsString($this->api->generateKey(256));
    }

    public function testGenerateKeyLength(): void {
        $this->assertSame(32, strlen($this->api->generateKey(256)));
    }

    public function testGenerateIvType(): void {
        $this->assertIsString($this->api->generateIv('AES-256-CBC'));
    }

    public function testGenerateIvLength(): void {
        $this->assertSame(16, strlen($this->api->generateIv('AES-256-CBC')));
    }

    public function testAesEncryptReturnTypes(): void {
        $this->assertSame(openSSLReturn::class, get_class($this->aesEncryptObject));
        $this->assertIsString($this->aesEncryptObject->getData());
        $this->assertIsString($this->aesEncryptObject->getKey());
        $this->assertIsString($this->aesEncryptObject->getIv());
        $this->assertIsString($this->aesEncryptObject->getAlgorithm());
        $this->assertIsBool($this->aesEncryptObject->getEncoded());
    }

    public function testBfEncryptReturnTypes(): void {
        $this->assertSame(openSSLReturn::class, get_class($this->bfEncryptObject));
        $this->assertIsString($this->bfEncryptObject->getData());
        $this->assertIsString($this->bfEncryptObject->getKey());
        $this->assertIsString($this->bfEncryptObject->getIv());
        $this->assertIsString($this->bfEncryptObject->getAlgorithm());
        $this->assertIsBool($this->bfEncryptObject->getEncoded());
    }

    public function testCast5EncryptReturnTypes(): void {
        $this->assertSame(openSSLReturn::class, get_class($this->cast5EncryptObject));
        $this->assertIsString($this->cast5EncryptObject->getData());
        $this->assertIsString($this->cast5EncryptObject->getKey());
        $this->assertIsString($this->cast5EncryptObject->getIv());
        $this->assertIsString($this->cast5EncryptObject->getAlgorithm());
        $this->assertIsBool($this->cast5EncryptObject->getEncoded());
    }

    public function testIDEAEncryptReturnTypes(): void {
        $this->assertSame(openSSLReturn::class, get_class($this->ideaEncryptObject));
        $this->assertIsString($this->ideaEncryptObject->getData());
        $this->assertIsString($this->ideaEncryptObject->getKey());
        $this->assertIsString($this->ideaEncryptObject->getIv());
        $this->assertIsString($this->ideaEncryptObject->getAlgorithm());
        $this->assertIsBool($this->ideaEncryptObject->getEncoded());
    }

    public function testCamelliaEncryptReturnTypes(): void {
        $this->assertSame(openSSLReturn::class, get_class($this->camelliaEncryptObject));
        $this->assertIsString($this->camelliaEncryptObject->getData());
        $this->assertIsString($this->camelliaEncryptObject->getKey());
        $this->assertIsString($this->camelliaEncryptObject->getIv());
        $this->assertIsString($this->camelliaEncryptObject->getAlgorithm());
        $this->assertIsBool($this->camelliaEncryptObject->getEncoded());
    }

    public function testChacha20EncryptReturnTypes(): void {
        $this->assertSame(openSSLReturn::class, get_class($this->chacha20EncryptObject));
        $this->assertIsString($this->chacha20EncryptObject->getData());
        $this->assertIsString($this->chacha20EncryptObject->getKey());
        $this->assertIsString($this->chacha20EncryptObject->getIv());
        $this->assertIsString($this->chacha20EncryptObject->getAlgorithm());
        $this->assertIsBool($this->chacha20EncryptObject->getEncoded());
    }

    public function testRSAKeyPairGenerationTypes(): void {
        $this->assertSame(openSSLKeyPairReturn::class, get_class($this->rsaKeyPairGeneration));
        $this->assertIsString($this->rsaKeyPairGeneration->getPrivateKey());
        $this->assertIsString($this->rsaKeyPairGeneration->getPublicKey());
        $this->assertIsInt($this->rsaKeyPairGeneration->getKeyLength());
        $this->assertIsString($this->rsaKeyPairGeneration->getDigestAlg());
    }

    public function testDSAKeyPairGenerationTypes(): void {
        $this->assertSame(openSSLKeyPairReturn::class, get_class($this->dsaKeyPairGeneration));
        $this->assertIsString($this->dsaKeyPairGeneration->getPrivateKey());
        $this->assertIsString($this->dsaKeyPairGeneration->getPublicKey());
        $this->assertIsInt($this->dsaKeyPairGeneration->getKeyLength());
        $this->assertIsString($this->dsaKeyPairGeneration->getDigestAlg());
    }

    public function testAesDecryptReturnTypes(): void {
        $this->assertSame(openSSLReturn::class, get_class($this->aesDecryptObject));
        $this->assertIsString($this->aesDecryptObject->getData());
        $this->assertIsString($this->aesDecryptObject->getKey());
        $this->assertIsString($this->aesDecryptObject->getIv());
        $this->assertIsString($this->aesDecryptObject->getAlgorithm());
        $this->assertIsBool($this->aesDecryptObject->getEncoded());
    }

    public function testBfDecryptReturnTypes(): void {
        $this->assertSame(openSSLReturn::class, get_class($this->bfDecryptObject));
        $this->assertIsString($this->bfDecryptObject->getData());
        $this->assertIsString($this->bfDecryptObject->getKey());
        $this->assertIsString($this->bfDecryptObject->getIv());
        $this->assertIsString($this->bfDecryptObject->getAlgorithm());
        $this->assertIsBool($this->bfDecryptObject->getEncoded());
    }

    public function testCast5DecryptReturnTypes(): void {
        $this->assertSame(openSSLReturn::class, get_class($this->cast5DecryptObject));
        $this->assertIsString($this->cast5DecryptObject->getData());
        $this->assertIsString($this->cast5DecryptObject->getKey());
        $this->assertIsString($this->cast5DecryptObject->getIv());
        $this->assertIsString($this->cast5DecryptObject->getAlgorithm());
        $this->assertIsBool($this->cast5DecryptObject->getEncoded());
    }

    public function testIDEADecryptReturnTypes(): void {
        $this->assertSame(openSSLReturn::class, get_class($this->ideaDecryptObject));
        $this->assertIsString($this->ideaDecryptObject->getData());
        $this->assertIsString($this->ideaDecryptObject->getKey());
        $this->assertIsString($this->ideaDecryptObject->getIv());
        $this->assertIsString($this->ideaDecryptObject->getAlgorithm());
        $this->assertIsBool($this->ideaDecryptObject->getEncoded());
    }

    public function testCamelliaDecryptReturnTypes(): void {
        $this->assertSame(openSSLReturn::class, get_class($this->camelliaDecryptObject));
        $this->assertIsString($this->camelliaDecryptObject->getData());
        $this->assertIsString($this->camelliaDecryptObject->getKey());
        $this->assertIsString($this->camelliaDecryptObject->getIv());
        $this->assertIsString($this->camelliaDecryptObject->getAlgorithm());
        $this->assertIsBool($this->camelliaDecryptObject->getEncoded());
    }

    public function testChacha20DecryptReturnTypes(): void {
        $this->assertSame(openSSLReturn::class, get_class($this->chacha20DecryptObject));
        $this->assertIsString($this->chacha20DecryptObject->getData());
        $this->assertIsString($this->chacha20DecryptObject->getKey());
        $this->assertIsString($this->chacha20DecryptObject->getIv());
        $this->assertIsString($this->chacha20DecryptObject->getAlgorithm());
        $this->assertIsBool($this->chacha20DecryptObject->getEncoded());
    }

}
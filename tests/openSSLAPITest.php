<?php
declare(strict_types=1);

use LLJVCS\PHPCryptoLib\openSSLAPI\openSSLAPI;
use LLJVCS\PHPCryptoLib\returnObjects\openSSLError;
use LLJVCS\PHPCryptoLib\returnObjects\openSSLKeyPairReturn;
use LLJVCS\PHPCryptoLib\returnObjects\openSSLReturn;
use PHPUnit\Framework\TestCase;

final class openSSLAPITest extends TestCase
{

    private $api;
    private $originalMessage;

    public function __construct(?string $name = null, array $data = [], string $dataName = '')
    {
        parent::__construct($name, $data, $dataName);
        $this->api = new openSSLAPI();
        $this->api->setEncoded(true);
        $this->originalMessage = 'Hello World!';
    }

    public function testCheckopenSSLAPIClassType(): void {
        $this->assertSame(openSSLAPI::class, get_class(new openSSLAPI()));
    }

    public function testopenSSLEnabled(): void {
        $this->assertTrue($this->api->checkopenSSLenabled());
    }

    public function testopenSSLEnabledFalse(): void {
        $this->assertFalse($this->api->checkopenSSLenabled(true));
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

    public function testAESEncryptReturnType(): void {
        $this->assertSame(openSSLReturn::class, get_class($this->api->AESencrypt($this->originalMessage)));
    }

    public function testAESDecryptReturnType(): void {
        $object = $this->api->AESencrypt($this->originalMessage);
        $this->assertSame(openSSLReturn::class, get_class($this->api->AESdecrypt($object->getData(), $object->getKey(), $object->getIv(), $object->getAlgorithm(), $object->getEncoded())));
    }

    public function testBfEncryptReturnType(): void {
        $this->assertSame(openSSLReturn::class, get_class($this->api->BFencrypt($this->originalMessage)));
    }

    public function testBfDecryptReturnType(): void {
        $object = $this->api->BFencrypt($this->originalMessage);
        $this->assertSame(openSSLReturn::class, get_class($this->api->BFdecrypt($object->getData(), $object->getKey(), $object->getIv(), $object->getAlgorithm(), $object->getEncoded())));
    }

    public function testCast5EncryptReturnType(): void {
        $this->assertSame(openSSLReturn::class, get_class($this->api->Cast5encrypt($this->originalMessage)));
    }

    public function testCast5DecryptReturnType(): void {
        $object = $this->api->Cast5encrypt($this->originalMessage);
        $this->assertSame(openSSLReturn::class, get_class($this->api->Cast5decrypt($object->getData(), $object->getKey(), $object->getIv(), $object->getAlgorithm(), $object->getEncoded())));
    }

    public function testIDEAEncryptReturnType(): void {
        $this->assertSame(openSSLReturn::class, get_class($this->api->IDEAencrypt($this->originalMessage)));
    }

    public function testIDEADecryptReturnType(): void {
        $object = $this->api->IDEAencrypt($this->originalMessage);
        $this->assertSame(openSSLReturn::class, get_class($this->api->IDEAdecrypt($object->getData(), $object->getKey(), $object->getIv(), $object->getAlgorithm(), $object->getEncoded())));
    }

    public function testCamelliaEncryptReturnType(): void {
        $this->assertSame(openSSLReturn::class, get_class($this->api->Camelliaencrypt($this->originalMessage)));
    }

    public function testCamelliaDecryptReturnType(): void {
        $object = $this->api->Camelliaencrypt($this->originalMessage);
        $this->assertSame(openSSLReturn::class, get_class($this->api->Camelliadecrypt($object->getData(), $object->getKey(), $object->getIv(), $object->getAlgorithm(), $object->getEncoded())));
    }

    public function testChacha20EncryptReturnType(): void {
        $this->assertSame(openSSLReturn::class, get_class($this->api->chacha20encrypt($this->originalMessage)));
    }

    public function testChacha20DecryptReturnType(): void {
        $object = $this->api->chacha20encrypt($this->originalMessage);
        $this->assertSame(openSSLReturn::class, get_class($this->api->chacha20decrypt($object->getData(), $object->getKey(), $object->getIv(), $object->getAlgorithm(), $object->getEncoded())));
    }

    public function testDESEDE3EncryptReturnType(): void {
        $this->assertSame(openSSLReturn::class, get_class($this->api->DESEDE3encrypt($this->originalMessage)));
    }

    public function testDESEDE3DecryptReturnType(): void {
        $object = $this->api->DESEDE3encrypt($this->originalMessage);
        $this->assertSame(openSSLReturn::class, get_class($this->api->DESEDE3decrypt($object->getData(), $object->getKey(), $object->getIv(), $object->getAlgorithm(), $object->getEncoded())));
    }

    public function testRSAKeyPairGenerationReturnType(): void {
        $this->assertSame(openSSLKeyPairReturn::class, get_class($this->api->RSAKeyPairGeneration()));
    }

    public function testDSAKeyPairGenerationReturnType(): void {
        $this->assertSame(openSSLKeyPairReturn::class, get_class($this->api->DSAKeyPairGeneration()));
    }

    public function testAESEncryptUnknownAlgorithmReturn(): void {
        $this->assertSame(openSSLError::class, get_class($this->api->AESencrypt($this->originalMessage, 'ABC', 4096)));
    }

}
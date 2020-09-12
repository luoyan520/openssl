<?php
declare (strict_types=1);

namespace LuoYan;

use think\exception\HttpException;
use think\facade\Env;

class OpenSSL
{
    /**
     * RSA需要用到的属性
     */
    private $publicKey;
    private $privateKey;

    /**
     * AES需要用到的属性
     *
     * @var string $key AES秘钥
     */
    private $key;

    /**
     * OpenSSL constructor.
     * 检测php openssl扩展是否开启
     */
    public function __construct()
    {
        if (!extension_loaded('openssl')) {
            throw new HttpException(500, '请开启PHP的openssl扩展！');
        }
    }

    /**
     * @param string $publicKeyFilename 公钥文件地址
     * @param string $privateKeyFilename 私钥文件地址
     * @param string $keyPassword 私钥密码
     * @return array code=0则初始化成功，msg表示返回消息
     */
    public function rsaInit(string $publicKeyFilename = '', string $privateKeyFilename = '', string $keyPassword = ''): array
    {
        $fp = fopen($publicKeyFilename, 'r');
        $publicKey = fread($fp, 8192);
        fclose($fp);
        $this->publicKey = openssl_get_publickey($publicKey);
        if (!$this->publicKey) {
            return ret_array(1, '无效的公钥！');
        }

        $fp = fopen($privateKeyFilename, 'r');
        $privateKey = fread($fp, 8192);
        fclose($fp);
        $this->privateKey = openssl_get_privatekey($privateKey, $keyPassword);
        unset($keyPassword);
        if (!$this->privateKey) {
            return ret_array(1, '无效的私钥！');
        }

        return ret_array(0, '初始化成功！');
    }

    /**
     * RSA公钥加密
     * @param string $string 需要加密的明文
     * @return array code=0则加密成功，msg表示密文或消息
     */
    public function rsaPublicEncrypt(string $string): array
    {
        if (!$this->publicKey) {
            return ret_array(3, '未初始化，请执行rsaInit方法！');
        }

        $result = '';
        $str_tmp = str_split($string, 100);

        foreach ($str_tmp as $value) {
            $result_tmp = '';
            if (openssl_public_encrypt($value, $result_tmp, $this->publicKey)) {
                $result .= $result_tmp . '[LY]';
            } else {
                return ret_array(2, '公钥加密失败！');
            }
            $result = rtrim($result, '[LY]');
        }

        $result = base64_encode($result);
        return ret_array(0, '', ['token' => $result]);
    }

    /**
     * RSA私钥加密
     * @param string $string 需要解密的明文
     * @return array code=0则加密成功，msg表示消息或密文
     */
    public function rsaPrivateEncrypt(string $string): array
    {
        if (!$this->privateKey) {
            return ret_array(3, '未初始化，请执行rsaInit方法！');
        }

        $result = '';
        $str_tmp = str_split($string, 100);

        foreach ($str_tmp as $value) {
            $result_tmp = '';
            if (openssl_private_encrypt($value, $result_tmp, $this->privateKey)) {
                $result .= $result_tmp . '[LY]';
            } else {
                return ret_array(2, '私钥加密失败！');
            }
            $result = rtrim($result, '[LY]');
        }

        $result = base64_encode($result);
        return ret_array(0, '', ['token' => $result]);
    }

    /**
     * RSA公钥解密
     * @param string $string 密文
     * @return array code=0则表示解密成功，msg为消息或明文
     */
    public function rsaPublicDecrypt(string $string): array
    {
        if (!$this->publicKey) {
            return ret_array(3, '未初始化，请执行rsaInit方法！');
        }

        $result = '';
        $string = base64_decode($string);
        $str_tmp = explode('[LY]', $string);

        foreach ($str_tmp as $value) {
            $result_tmp = '';
            $cache = openssl_public_decrypt($value, $result_tmp, $this->publicKey);
            if ($cache) {
                $result .= $result_tmp;
            } else {
                return ret_array(2, '公钥解密失败！');
            }
        }

        return ret_array(0, '', ['text' => $result]);
    }

    /**
     * RSA私钥解密
     * @param string $string
     * @return array code=0则表示解密成功，msg表示明文或消息
     */
    public function rsaPrivateDecrypt(string $string): array
    {
        if (!$this->privateKey) {
            return ret_array(3, '未初始化，请执行rsaInit方法！');
        }

        $result = '';
        $string = base64_decode($string);
        $str_tmp = explode('[LY]', $string);

        foreach ($str_tmp as $value) {
            $result_tmp = '';
            if (openssl_private_decrypt($value, $result_tmp, $this->privateKey)) {
                $result .= $result_tmp;
            } else {
                return ret_array(2, '私钥解密失败！');
            }
        }

        return ret_array(0, '', ['text' => $result]);
    }

    /**
     * RSA签名
     *
     * @param string $string 要签名的内容
     * @return array $code 签名结果
     * @return array
     */
    public function rsaSign(string $string): array
    {
        openssl_sign($string, $signature, $this->privateKey);
        if ($signature) {
            $signature = base64_encode($signature);
            return ret_array(0, '', ['sign' => $signature]);
        } else {
            return ret_array(4, '签名失败！');
        }
    }

    /**
     * RSA验签
     *
     * @param string $signature 签名
     * @param string $string 要验证的明文
     * @return bool
     */
    public function rsaVerify(string $signature, string $string): bool
    {
        $signature = base64_decode($signature);
        if (!$signature) return false;
        $result = openssl_verify($string, $signature, $this->publicKey);
        if ($result) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * 初始化AES加密密钥
     * @param string $key 密钥
     */
    public function aesInit(string $key = ''): void
    {
        if (!$key) $key = Env::get('System.Security_key', 'LuoYan');
        $key = hash('sha256', $key, false);
        $this->key = $key;
    }

    /**
     * AES加密
     * @param string $string
     * @return array code=0则加密成功，msg为消息或密文
     */
    public function aesEncrypt(string $string): array
    {
        if (!$this->key) {
            return ret_array(3, '未初始化，请执行aesInit方法！');
        }

        $result = openssl_encrypt($string, 'AES-128-ECB', $this->key, OPENSSL_RAW_DATA);
        $result = base64_encode($result);
        return ret_array(0, '', ['token' => $result]);
    }

    /**
     * AES解密
     * @param $string
     * @return array code=0则解密成功，msg为消息或明文
     */
    public function aesDecrypt(string $string): array
    {
        if (!$this->key) {
            return ret_array(3, '未初始化，请执行aesInit方法！');
        }

        $string = base64_decode($string);
        $result = openssl_decrypt($string, 'AES-128-ECB', $this->key, OPENSSL_RAW_DATA);
        return ret_array(0, '', ['text' => $result]);
    }

    /**
     * 析构方法，释放公钥私钥资源
     */
    public function __destruct()
    {
        is_resource($this->privateKey) && @openssl_free_key($this->privateKey);
        is_resource($this->publicKey) && @openssl_free_key($this->publicKey);
    }
}

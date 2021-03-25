<?php
declare (strict_types=1);

namespace LuoYan;

use Exception;
use think\exception\HttpException;

class OpenSSL
{
    /**
     * RSA需要用到的属性
     * @var resource $publicKey 公钥
     * @var resource $privateKey 私钥
     */
    private $publicKey;
    private $privateKey;

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
     * AES加密
     * @param string $string 要加密的内容
     * @param string $key 秘钥
     * @return string 密文
     * @throws Exception
     */
    public static function aesEncrypt(string $string, string $key): string
    {
        $result = openssl_encrypt($string, 'AES-128-ECB', $key, OPENSSL_RAW_DATA);
        $result = base64_encode($result);
        return $result;
    }

    /**
     * AES解密
     * @param string $string 要解密的内容
     * @param string $key 秘钥
     * @return string 明文
     */
    public static function aesDecrypt(string $string, string $key): string
    {
        $string = base64_decode($string);
        return openssl_decrypt($string, 'AES-128-ECB', $key, OPENSSL_RAW_DATA);
    }

    /**
     * @param string $publicKeyFilename 公钥文件地址
     * @param string $privateKeyFilename 私钥文件地址
     * @param string $keyPassword 私钥密码
     * @return array code=0则初始化成功，msg表示返回消息
     */
    public function rsaInit(string $publicKeyFilename = '', string $privateKeyFilename = '', string $keyPassword = ''): array
    {
        if ($publicKeyFilename) {
            // 读公钥
            $fp = fopen($publicKeyFilename, 'r');
            $public_key = fread($fp, 8192);
            fclose($fp);

            // 取出并校验公钥
            $public_key = openssl_pkey_get_public($public_key);
            if (!$public_key) return ['code' => 1, 'msg' => '无效的公钥'];

            // 将公钥保存到属性
            $this->publicKey = $public_key;
        }

        if ($privateKeyFilename) {
            // 读私钥
            $fp = fopen($privateKeyFilename, 'r');
            $private_key = fread($fp, 8192);
            fclose($fp);

            // 取出并校验私钥
            $private_key = openssl_pkey_get_private($private_key, $keyPassword);
            unset($keyPassword);
            if (!$private_key) return ['code' => 2, 'msg' => '无效的私钥'];

            // 将私钥保存到属性
            $this->privateKey = $private_key;
        }

        return ['code' => 0, 'msg' => '初始化成功'];
    }

    /**
     * RSA公钥加密
     * @param string $string 需要加密的明文
     * @return array code=0则加密成功，msg表示密文或消息
     */
    public function rsaPublicEncrypt(string $string): array
    {
        // 检测是否已经进行RSA初始化
        if (!$this->publicKey) return ['code' => 1, 'msg' => '未初始化，请执行RSAInit方法'];

        // 初始化结果变量
        $result = '';
        // 分割需要加密的文本，每100个字符一份
        $str_tmp = str_split($string, 100);

        // 开始循环加密需要加密的文本
        foreach ($str_tmp as $value) {
            $result_tmp = '';
            if (openssl_public_encrypt($value, $result_tmp, $this->publicKey)) {
                // 加密成功，添加到结果，并标记分隔符
                $result .= $result_tmp . '[LY]';
            } else {
                // 加密失败，直接退出
                return ['code' => 2, 'msg' => '公钥加密失败'];
            }
        }

        // 去除最后一个无效的分割符
        $result = rtrim($result, '[LY]');
        // base64编码
        $result = base64_encode($result);
        // 返回结果
        return ['code' => 0, 'msg' => '', ['data' => ['token' => $result]]];
    }

    /**
     * RSA私钥加密
     * @param string $string 需要解密的明文
     * @return array code=0则加密成功，msg表示消息或密文
     */
    public function rsaPrivateEncrypt(string $string): array
    {
        // 检测是否已经进行RSA初始化
        if (!$this->privateKey) return ['code' => 1, 'msg' => '未初始化，请执行RsaInit方法'];

        // 初始化结果变量
        $result = '';
        // 分割需要加密的文本，每100个字符一份
        $str_tmp = str_split($string, 100);

        // 开始循环加密需要加密的文本
        foreach ($str_tmp as $value) {
            $result_tmp = '';
            if (openssl_private_encrypt($value, $result_tmp, $this->privateKey)) {
                // 加密成功，添加到结果，并标记分隔符
                $result .= $result_tmp . '[LY]';
            } else {
                // 加密失败，直接退出
                return ['code' => 2, 'msg' => '私钥加密失败'];
            }
        }

        // 去除最后一个无效的分割符
        $result = rtrim($result, '[LY]');
        // base64编码
        $result = base64_encode($result);
        // 返回结果
        return ['code' => 0, 'msg' => '', ['data' => ['token' => $result]]];
    }

    /**
     * RSA公钥解密
     * @param string $string 密文
     * @return array code=0则表示解密成功，msg为消息或明文
     */
    public function rsaPublicDecrypt(string $string): array
    {
        // 检测是否已经进行RSA初始化
        if (!$this->publicKey) return ['code' => 1, 'msg' => '未初始化，请执行RsaInit方法'];

        // 初始化结果变量
        $result = '';
        // base64解码待解密的文本
        $string = base64_decode($string);
        // 通过分隔符进行分离待解密的文本集
        $str_tmp = explode('[LY]', $string);

        foreach ($str_tmp as $value) {
            $result_tmp = '';
            $cache = openssl_public_decrypt($value, $result_tmp, $this->publicKey);
            if ($cache) {
                // 解密成功，添加到结果
                $result .= $result_tmp;
            } else {
                // 解密失败，直接退出
                return ['code' => 2, 'msg' => '公钥解密失败'];
            }
        }

        // 返回
        return ['code' => 0, 'msg' => '', ['data' => ['text' => $result]]];
    }

    /**
     * RSA私钥解密
     * @param string $string
     * @return array code=0则表示解密成功，msg表示明文或消息
     */
    public function rsaPrivateDecrypt(string $string): array
    {
        // 检测是否已经进行RSA初始化
        if (!$this->privateKey) return ['code' => 1, 'msg' => '未初始化，请执行RsaInit方法'];

        // 初始化结果变量
        $result = '';
        // base64解码待解密的文本
        $string = base64_decode($string);
        // 通过分隔符进行分离待解密的文本集
        $str_tmp = explode('[LY]', $string);

        foreach ($str_tmp as $value) {
            $result_tmp = '';
            if (openssl_private_decrypt($value, $result_tmp, $this->privateKey)) {
                // 解密成功，添加到结果
                $result .= $result_tmp;
            } else {
                // 解密失败，直接退出
                return ['code' => 2, 'msg' => '私钥解密失败'];
            }
        }

        // 返回
        return ['code' => 0, 'msg' => '', ['data' => ['text' => $result]]];
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
            // base64编码签名
            $signature = base64_encode($signature);
            return ['code' => 0, 'msg' => '', ['data' => ['sign' => $signature]]];
        } else {
            return ['code' => 1, 'msg' => '私钥签名失败'];
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
        // base64解码签名
        $signature = base64_decode($signature);
        if (!$signature) return false;
        $result = openssl_verify($string, $signature, $this->publicKey);

        return $result ? true : false;
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

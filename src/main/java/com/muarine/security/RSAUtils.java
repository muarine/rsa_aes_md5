/**  
 * @Title: RSAUtils.java
 * @Package com.muarine.Auto.rsa
 * @Description:
 * @author maoyun0903(maoyun0903@163.com)
 * @date 2015-6-16 下午09:36:33
 * @version V1.0
 */ 
package com.muarine.security;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/** 
 * @ClassName: RSAUtils 
 * @Description: RSA加密
 * @author maoyun0903(maoyun0903@163.com)
 * @date 2015-6-16 下午09:36:33 
 * @version V1.0
 */

public class RSAUtils {
	
	/**
	 * RSA加密
	 */
	public static final String KEY_ALGORTHM="RSA";//
	/**
	 *  签名算法
	 */
	public static final String SIGNATURE_ALGORITHM="SHA1withRSA";
//	public static final String SIGNATURE_ALGORITHM="NONEwithRSA";
//	public static final String SIGNATURE_ALGORITHM="MD5withRSA";
	 
	public static final String PUBLIC_KEY = "RSAPublicKey";//公钥
	public static final String PRIVATE_KEY = "RSAPrivateKey";//私钥
	
	public static void main(String[] args) throws Exception{
		
		Map<String, Object> map = RSAUtils.initKey();
		String publicKey = RSAUtils.getPublicKey(map);
		String privateKey = RSAUtils.getPrivateKey(map);
		String data = "ABC";
		
		byte[] en = RSAUtils.encryptByPublicKey(data.getBytes(), publicKey);
		System.out.println("密文：" + toHexString(en));
		byte[] de = RSAUtils.decryptByPrivateKey(en, privateKey);
		System.out.println("解密结果：" + new String(de));
		
		byte[] enc = RSAUtils.encryptByPrivateKey(data.getBytes(), privateKey);
		byte[] dec = RSAUtils.decryptByPublicKey(enc, publicKey);
		System.out.println("私钥加密：" + toHexString(enc));
		System.out.println("公钥解密：" + new String(dec));
		byte[] md5 = MD5Utils.getMD5String(data);
		System.out.println("md5:" + md5);
		String sign = RSAUtils.sign(md5, privateKey);
		boolean flag = RSAUtils.verify(md5, publicKey, sign);
		System.out.println("sign签名：" + sign);
		System.out.println("校验签名：" + flag);
		
		// AES 加密解密
		// 1. 随机生成 key/iv
		SecretKey secretKey = AESUtil.getSecretKey();
		IvParameterSpec ivParameterSpec = AESUtil.getIv();
		// 2. AES 加密
		byte[] aes_en = AESUtil.encrypt(data, secretKey, ivParameterSpec);
		String aes_de = AESUtil.decrypt(Base64Utils.encode(aes_en), secretKey, ivParameterSpec);
		System.out.println("AES原文：" + data);
		System.out.println("AES密文(16进制)：" + toHexString(aes_en));
		System.out.println("AES解密：" + aes_de);
		// 3. key/iv 二进制转十六进制 
		String key = toHexString(secretKey.getEncoded());
		String iv = toHexString(ivParameterSpec.getIV());
//		System.out.println("AES key length:" + secretKey.getEncoded().length);
//		System.out.println("AES iv length:" + ivParameterSpec.getIV().length);
		System.out.println("AES key(16进制):" + key);
		// 4. RSA加密十六进制的key和iv
		System.out.println("AES key(RSA密文):" + toHexString(RSAUtils.encryptByPublicKey(key.getBytes(), publicKey)));
//		System.out.println("AES byte key:" + new String(secretKey.getEncoded()));
		System.out.println("AES iv(16进制):" + iv);
		System.out.println("AES iv(RSA密文):" + toHexString(RSAUtils.encryptByPublicKey(iv.getBytes(), publicKey)));
//		System.out.println("AES byte iv:" + new String(ivParameterSpec.getIV()));
		
	}
	
	
	/**
     * 初始化密钥
     * @return
     * @throws Exception
     */
    public static Map<String,Object> initKey()throws Exception{
    	
    	KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] encodedKey = input2byte(RSAUtils.class.getResourceAsStream("private_key.pem"));
        RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Base64Utils.decode(new String(encodedKey))));
        
        
//        byte[] encodedKey2 = input2byte(RSAUtils.class.getResourceAsStream("rsa_public_key.pem"));
//        KeySpec keySpec =  new  X509EncodedKeySpec(Base64Utils.decode(new String(encodedKey2)));  
//        RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
        
        CertificateFactory certificatefactory=CertificateFactory.getInstance("X.509");
		InputStream input = RSAUtils.class.getResourceAsStream("rsa_public_key.pem.crt");
		X509Certificate Cert = (X509Certificate)certificatefactory.generateCertificate(input);
		RSAPublicKey publicKey = (RSAPublicKey) Cert.getPublicKey();
    	
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORTHM);
//        keyPairGenerator.initialize(1024);
//        KeyPair keyPair = keyPairGenerator.generateKeyPair();
         
        //公钥
//        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        //私钥
//        RSAPrivateKey privateKey =  (RSAPrivateKey) keyPair.getPrivate();
         
        Map<String,Object> keyMap = new HashMap<String, Object>(2);
        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY, privateKey);
         
        return keyMap;
    }
    
    public static final byte[] input2byte(InputStream inStream) throws IOException {  
		ByteArrayOutputStream swapStream = new ByteArrayOutputStream();  
		byte[] buff = new byte[100];  
		int rc = 0;  
		while ((rc = inStream.read(buff, 0, 100)) > 0) {  
		    swapStream.write(buff, 0, rc);  
		}  
		byte[] in2b = swapStream.toByteArray();  
		return in2b;  
	}  
	
    
    /**
     * 取得公钥，并转化为String类型
     * @param keyMap
     * @return
     * @throws Exception
     */
    public static String getPublicKey(Map<String, Object> keyMap)throws Exception{
        Key key = (Key) keyMap.get(PUBLIC_KEY);  
        return Coder.encryptBASE64(key.getEncoded());     
    }
 
    /**
     * 取得私钥，并转化为String类型
     * @param keyMap
     * @return
     * @throws Exception
     */
    public static String getPrivateKey(Map<String, Object> keyMap) throws Exception{
        Key key = (Key) keyMap.get(PRIVATE_KEY);  
        return Coder.encryptBASE64(key.getEncoded());     
    }
    
    /**
     * 用私钥加密
     * @param data  加密数据
     * @param key   密钥
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPrivateKey(byte[] data,String key)throws Exception{
        //解密密钥
        byte[] keyBytes = Coder.decryptBASE64(key);
        //取私钥
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORTHM);
        Key privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
         
        //对数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
         
        return cipher.doFinal(data);
    }
    
    
    /**
     * 用私钥解密<span style="color:#000000;"></span> * @param data  加密数据
     * @param key   密钥
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] data,String key)throws Exception{
        //对私钥解密
        byte[] keyBytes = Coder.decryptBASE64(key);
         
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORTHM);
        Key privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        //对数据解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
         
        return cipher.doFinal(data);
    }
    
    
    /**
     * 用公钥加密
     * @param data  加密数据
     * @param key   密钥
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(byte[] data,String key)throws Exception{
        //对公钥解密
        byte[] keyBytes = Coder.decryptBASE64(key);
        //取公钥
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORTHM);
        Key publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
         
        //对数据解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
         
        return cipher.doFinal(data);
    }
    
    
    /**
     * 用公钥解密
     * @param data  加密数据
     * @param key   密钥
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPublicKey(byte[] data,String key)throws Exception{
        //对私钥解密
        byte[] keyBytes = Coder.decryptBASE64(key);
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORTHM);
        Key publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
         
        //对数据解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
         
        return cipher.doFinal(data);
    }
    
    
    /**
     *  用私钥对信息生成数字签名
     * @param data  //加密数据
     * @param privateKey    //私钥
     * @return
     * @throws Exception
     */
    public static String sign(byte[] data,String privateKey)throws Exception{
        //解密私钥
        byte[] keyBytes = Coder.decryptBASE64(privateKey);
        //构造PKCS8EncodedKeySpec对象
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);
        //指定加密算法
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORTHM);
        //取私钥匙对象
        PrivateKey privateKey2 = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        //用私钥对信息生成数字签名
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey2);
        signature.update(data);
         
        return toHexString(signature.sign());
    }
    
    
    /**
     * 校验数字签名
     * @param data  加密数据
     * @param publicKey 公钥
     * @param sign  数字签名
     * @return
     * @throws Exception
     */
    public static boolean verify(byte[] data,String publicKey,String sign)throws Exception{
        //解密公钥
        byte[] keyBytes = Coder.decryptBASE64(publicKey);
        //构造X509EncodedKeySpec对象
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
        //指定加密算法
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORTHM);
        //取公钥匙对象
        PublicKey publicKey2 = keyFactory.generatePublic(x509EncodedKeySpec);
         
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicKey2);
        signature.update(data);
        //验证签名是否正常
        return signature.verify(toBytes(sign));
         
    }
    
    /**
	 * Md5参数签名 
	 * @param merchantCode
	 * @param rsa_random_num
	 * @param rsa_time_flag
	 * @return String
	 */
	public static byte[] matchKey(String merchantCode, String rsa_random_num,
			String rsa_time_flag) {
		StringBuffer sb = new StringBuffer();
		sb.append("merchantCode=")
			.append(merchantCode)
			.append("&")
			.append("rsa_random_num=")
			.append(rsa_random_num)
			.append("&")
			.append("rsa_time_flag=")
			.append(rsa_time_flag);
		
		return MD5Utils.getMD5String(sb.toString());
	}
	
	/**
     * 获取一定长度的随机字符串
     * @param length 指定字符串长度
     * @return 一定长度的字符串
     */
    public static String getRandomStringByLength(int length) {
        String base = "abcdefghijklmnopqrstuvwxyz0123456789";
        Random random = new Random();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < length; i++) {
            int number = random.nextInt(base.length());
            sb.append(base.charAt(number));
        }
        return sb.toString();
    }
	
	/**
     * 字节数组转十六进制
     */
    public static String toHexString(byte[] b) {   
        StringBuilder sb = new StringBuilder(b.length * 2);   
        for (int i = 0; i < b.length; i++) {   
            sb.append(HEXCHAR[(b[i] & 0xf0) >>> 4]);   
            sb.append(HEXCHAR[b[i] & 0x0f]);   
        }   
        return sb.toString();
    }
  
    /**
     * 十六进制转byte
     * FIXME Comment this
     * 
     * @param s
     * @return
     */
    public static final byte[] toBytes(String s) {   
        byte[] bytes;   
        bytes = new byte[s.length() / 2];   
        for (int i = 0; i < bytes.length; i++) {   
            bytes[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2),   
                    16);   
        }   
        return bytes;   
    }  
    
    private static char[] HEXCHAR = { '0', '1', '2', '3', '4', '5', '6', '7',   
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };  
    
}

package com.muarine.security;

import java.security.MessageDigest;

import org.apache.commons.codec.binary.Base64;


 
public class Coder {
     
    public static final String KEY_SHA="SHA";
    public static final String KEY_MD5="MD5";
     
    /**
     * BASE64解密
     * @param key
     * @return
     * @throws Exception
     */
	public static byte[] decryptBASE64(String key) throws Exception{
        return Base64.decodeBase64(key);
    }
     
    /**
     * BASE64加密
     * @param key
     * @return
     * @throws Exception
     */
    public static String encryptBASE64(byte[] key)throws Exception{
        return Base64.encodeBase64String(key);
    }
     
    /**
     * MD5加密
     * @param data
     * @return
     * @throws Exception
     */
    public static byte[] encryptMD5(byte[] data)throws Exception{
        MessageDigest md5 = MessageDigest.getInstance(KEY_MD5);
        md5.update(data);
        return md5.digest();
    }
     
    /**
     * SHA加密
     * @param data
     * @return
     * @throws Exception
     */
    public static byte[] encryptSHA(byte[] data)throws Exception{
        MessageDigest sha = MessageDigest.getInstance(KEY_SHA);
        sha.update(data);
        return sha.digest();
    }
}
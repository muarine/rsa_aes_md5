package com.muarine.security;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;


public enum AESUtil {
	;
	/** 
     * 密钥算法 
     * java6支持56位密钥，bouncycastle支持64位 
     * */ 
    public static final String KEY_ALGORITHM = "AES"; 
	/** 
     * 加密/解密算法/工作模式/填充方式 
     *  
     * JAVA6 支持PKCS5PADDING填充方式 
     * Bouncy castle支持PKCS7Padding填充方式 
     * */ 
    public static final String CIPHER_ALGORITHM="AES/CBC/PKCS5Padding";
	
    /**
     * 生成Key
     * FIXME Comment this
     * 
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static SecretKey getSecretKey() throws NoSuchAlgorithmException{
    	
    	KeyGenerator generator = KeyGenerator.getInstance(KEY_ALGORITHM);
    	generator.init(256);
    	SecretKey key = generator.generateKey();
    	return key;
    	
    }
    
    /**
     * 生成IV
     * FIXME Comment this
     * 
     * @return
     */
    public static IvParameterSpec getIv(){
    	
    	SecureRandom rnd = new SecureRandom();
    	IvParameterSpec iv = new IvParameterSpec(rnd.generateSeed(16));
    	return iv;
    			
    }
    
    /**
     * 
     * 加密
     * @param src
     * @return
     * @throws Exception 
     */
	public static byte[] encrypt(String src , SecretKey k , IvParameterSpec iv) throws Exception{
		Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, k, iv);
		return cipher.doFinal(src.getBytes());
	}
	
	/** 
	 * 加密 
	 *  
	 * @param content 需要加密的内容 
	 * @param password  加密密码 
	 * @return 
	 */  
	public static byte[] encrypt(String content, String password) {  
		try {             
            KeyGenerator kgen = KeyGenerator.getInstance("AES");  
            kgen.init(256, new SecureRandom(password.getBytes()));  
            SecretKey secretKey = kgen.generateKey();  
            byte[] enCodeFormat = secretKey.getEncoded();  
            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");  
            Cipher cipher = Cipher.getInstance("AES");// 创建密码器   
            byte[] byteContent = content.getBytes("utf-8");  
            cipher.init(Cipher.ENCRYPT_MODE, key);// 初始化   
            byte[] re = cipher.doFinal(byteContent);  
            
            return re; // 加密   
        } catch (NoSuchAlgorithmException e) {  
                e.printStackTrace();  
        } catch (NoSuchPaddingException e) {  
                e.printStackTrace();  
        } catch (InvalidKeyException e) {  
                e.printStackTrace();  
        } catch (UnsupportedEncodingException e) {  
                e.printStackTrace();  
        } catch (IllegalBlockSizeException e) {  
                e.printStackTrace();  
        } catch (BadPaddingException e) {  
                e.printStackTrace();  
        }  
        return null;  
	}  
	/**
	 * 
	 * 解密
	 * @param src
	 * @return
	 */
	public static String decrypt(String src , SecretKey k , IvParameterSpec iv) {
		String decrypted = "";
		try {
			Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE, k, iv);
			decrypted = new String(cipher.doFinal(new Base64().decode(src)));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		return decrypted;
	}
	
	
}

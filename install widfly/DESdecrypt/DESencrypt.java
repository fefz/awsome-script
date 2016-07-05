package com.xiaojianya.util;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import android.util.Base64;

public class EncryptionHelper {

    private static final String Algorithm = "DESede"; // 定义加密算法3DES
    public static final String DEFAULT_KEY = "youjiaqcode";

    public static String decrypt3DES(String value, String key) throws Exception {
        byte[] b = decryptMode(getKeyBytes(key), Base64.decode(value, Base64.DEFAULT));
        return new String(b);
    }

    public static String encrypt3DES(String value, String key) throws Exception {
        String str = byte2Base64(encryptMode(getKeyBytes(key), value.getBytes()));
        return str;
    }

    // 计算24位长的密码byte值,首先对原始密钥做MD5算hash值，再用前8位数据对应补全后8位
    public static byte[] getKeyBytes(String strKey) throws Exception {

        if (null == strKey || strKey.length() < 1) {
            throw new Exception("key is null or empty!");
        }

        java.security.MessageDigest alg = java.security.MessageDigest
                .getInstance("MD5");
        alg.update(strKey.getBytes());
        byte[] bkey = alg.digest();
        int start = bkey.length;
        byte[] bkey24 = new byte[24];
        for (int i = 0; i < start; i++) {
            bkey24[i] = bkey[i];
        }

        for (int i = start; i < 24; i++) {// 为了与.net16位key兼容
            bkey24[i] = bkey[i - start];
        }

        return bkey24;
    }

    public static byte[] encryptMode(byte[] keybyte, byte[] src) {

        try {
            // 生成密钥
            SecretKey deskey = new SecretKeySpec(keybyte, Algorithm); // 加密
            Cipher c1 = Cipher.getInstance(Algorithm);
            c1.init(Cipher.ENCRYPT_MODE, deskey);
            return c1.doFinal(src);
        } catch (java.security.NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        } catch (javax.crypto.NoSuchPaddingException e2) {
            e2.printStackTrace();
        } catch (java.lang.Exception e3) {
            e3.printStackTrace();
        }
        return null;
    }

    // keybyte为加密密钥，长度为24字节

    // src为加密后的缓冲区

    public static byte[] decryptMode(byte[] keybyte, byte[] src) {

        try { // 生成密钥
            SecretKey deskey = new SecretKeySpec(keybyte, Algorithm);
            // 解密
            Cipher c1 = Cipher.getInstance(Algorithm);
            c1.init(Cipher.DECRYPT_MODE, deskey);
            return c1.doFinal(src);
        } catch (java.security.NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        } catch (javax.crypto.NoSuchPaddingException e2) {
            e2.printStackTrace();
        } catch (java.lang.Exception e3) {
            e3.printStackTrace();
        }
        return null;
    }

    //转换成base64编码
    public static String byte2Base64(byte[] b) {
        return Base64.encodeToString(b, Base64.DEFAULT);
    }

}

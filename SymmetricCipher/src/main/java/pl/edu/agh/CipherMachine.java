package pl.edu.agh;


import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.Security;

import java.security.spec.KeySpec;
import java.util.concurrent.atomic.AtomicReference;


public class CipherMachine {

    private AtomicReference<Cipher> cipher;
    private AtomicReference<SecretKey> secretKey;
    private final int providerInd;
    private final String initVector = "abcdabcdabcdabcd";

    public CipherMachine() {
        providerInd = Security.addProvider(new BouncyCastleProvider());

        init();
    }

    private void init() {
        try {
            byte[] keyData = "Bar12345Bar12345".getBytes("UTF-8");
            SecretKeySpec desKeySpec = new SecretKeySpec(keyData, "AES");
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("AES");
            secretKey = new AtomicReference<>(keyFactory.generateSecret(desKeySpec));
            cipher = new AtomicReference<>(Cipher.getInstance("AES/CBC/PKCS7Padding"));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public byte[] encrypt(byte[] message) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
        cipher.get().init(Cipher.ENCRYPT_MODE, secretKey.get(), iv);
        return cipher.get().doFinal(message);
    }

    public byte[] decrypt(byte[] message) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
        cipher.get().init(Cipher.DECRYPT_MODE, secretKey.get(), iv);

        return cipher.get().doFinal(message);
    }


}

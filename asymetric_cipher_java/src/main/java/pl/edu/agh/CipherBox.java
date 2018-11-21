package pl.edu.agh;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import static java.lang.Math.min;

/**
 * Created by raph on 07/11/2017.
 */
public class CipherBox {
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private int bitLength;
    public CipherBox(){
        Security.addProvider(new BouncyCastleProvider());
    }

    public void loadPrivateKey(String filename){
        try {
            Security.addProvider(new BouncyCastleProvider());
            PemReader pemReader = new PemReader(new InputStreamReader(new FileInputStream(filename)));
            PemObject pemObject = pemReader.readPemObject();
            KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
            byte[] content = pemObject.getContent();
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
            this.privateKey=factory.generatePrivate(privKeySpec);
            RSAPrivateKey r = (RSAPrivateKey)this.privateKey;
            this.bitLength = r.getModulus().bitLength();
        } catch (Exception ex){
            System.out.print("IO Exception");
        }
    }
    public void loadPublicKey(String filename){
        try {
            Security.addProvider(new BouncyCastleProvider());
            PemReader pemReader = new PemReader(new InputStreamReader(new FileInputStream(filename)));
            PemObject pemObject = pemReader.readPemObject();
            KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
            byte[] content = pemObject.getContent();
            //System.out.write(content);
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
            this.publicKey=factory.generatePublic(pubKeySpec);
            RSAPublicKey r = (RSAPublicKey)this.publicKey;
            this.bitLength = r.getModulus().bitLength();
        } catch (Exception ex){
            System.out.print("IO Exception");
        }
    }


    public byte[] encrypt(byte [] message)  {
        byte [] ct = new byte[0];
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE | Cipher.PUBLIC_KEY , this.publicKey);
            for(int i=0; i < message.length; i+=this.bitLength/8-11){
                 ct = append(ct,cipher.doFinal(message,i,min(this.bitLength/8-11,message.length - i)));
            }
            return ct;
        } catch (Exception ex){
            ex.printStackTrace();
            System.out.println("Error in encryption");
        }
        return null;
    }
    public byte[] decrypt(byte [] message)  {
        try {
            byte [] pt = new byte[0];
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
            for(int i=0; i < message.length; i+=this.bitLength/8){
                pt = append(pt,cipher.doFinal(message,i,min(this.bitLength/8,message.length - i)));
            }
            return pt;
        } catch (Exception ex){
            ex.printStackTrace();
            System.out.println("Error in decryption");
        }
        return null;
    }
    private byte[] append(byte[] prefix, byte[] suffix){
        byte[] toReturn = new byte[prefix.length + suffix.length];
        for (int i=0; i< prefix.length; i++){
            toReturn[i] = prefix[i];
        }
        for (int i=0; i< suffix.length; i++){
            toReturn[i+prefix.length] = suffix[i];
        }
        return toReturn;
    }
}

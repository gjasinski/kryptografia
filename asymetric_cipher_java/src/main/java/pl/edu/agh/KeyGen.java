package pl.edu.agh;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Created by raph on 06/11/2017.
 */
public class KeyGen {
    int keySize;
    String privateKey, publicKey;
    KeyPairGenerator keyPairGenerator;
    KeyPair keyPair;
    public KeyGen(int keySize, String priv, String pub){
        this.keySize = keySize;
        this.privateKey = priv;
        this.publicKey = pub;
    }
    public void generateKeys(){
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");

            //Generator liczb losowych, które spełniają pewne warunki specyficzne
            //dla kryptografii, np. nie można przewidzieć kolejnej generowanej liczby
            //na podstawie poprzednich. Oczywiście muszą też spełniać wszystkie normalne
            //testy statystyczne.
            //SHA1PRNG (Initial seeding is currently done via a combination of system attributes
            // and the java.security entropy gathering device)
            //inne: NativePRNG używa /dev/urandom i /dev/random
            //NativePRNGBlocking - problem z entropią, aplikacja może wisieć

            SecureRandom random = SecureRandom.getInstance("NativePRNG");

            //Jak wybrać najsilniejszy algorytm? Proszę uważać!
            /*SecureRandom random = SecureRandom.getInstanceStrong();*/
            System.out.println(random.getAlgorithm());

            //NativePRNGBlocking will be problematic in any applications where you do
            // not want your application to block while the system gathers more entropy.
            // Getting any type of output from it could cause your application’s thread to hang.
            // It is fine for use in a desktop application for generating a local cryptographic
            // key (for example), but will almost never be okay to use in a web application.

            //Note that NativePRNGBlocking can be somewhat wasteful in its entropy usage.
            // For performance reasons, it will read in 32 bytes of data at a time from /dev/random
            // for nextBytes(), nextInt(), etc. Any data that doesn’t get used within 100 milliseconds
            // will be discarded. As a result, each call to nextBoolean() will give you one bit of output,
            // but the implementation may actually use up (and mostly discard) 256 bits of entropy.


            keyPairGenerator.initialize(keySize, random);
            this.keyPair = keyPairGenerator.generateKeyPair();

            this.savePrivateKey(privateKey, publicKey);
            //System.out.print(r.getPrivateExponent());
        } catch (NoSuchAlgorithmException ex){
            System.out.print("Wrong algorithm");
        }
    }
    public void savePrivateKey(String filenamePriv, String filenamePub){
        keyPair.getPrivate().getEncoded();
        try {
            PemWriter pemWriterPriv = new PemWriter(new OutputStreamWriter(new FileOutputStream(filenamePriv)));
            System.out.println("Private key format"+this.keyPair.getPrivate().getFormat());
            pemWriterPriv.writeObject(new PemObject("RSA PRIVATE KEY",this.keyPair.getPrivate().getEncoded()));
            PemWriter pemWriterPub = new PemWriter(new OutputStreamWriter(new FileOutputStream(filenamePub)));
            System.out.println("Public key format"+this.keyPair.getPublic().getFormat());
            pemWriterPub.writeObject(new PemObject("RSA PUBLIC KEY",this.keyPair.getPublic().getEncoded()));
            pemWriterPub.close();
            pemWriterPriv.close();
        } catch (IOException ex){
            System.out.print("IO Exception");
        }
    }
}

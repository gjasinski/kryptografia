package pl.edu.agh;

import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.lang.String;
import java.security.interfaces.RSAPrivateKey;


public class Main {

    public static void main(String[] args) {
        for (int i = 0; i < args.length; i++) {
            System.out.println("Argument is: " + args[i]);
        }
        String privateKey = "rsa.priv";
        String publicKey = "rsa.pub";
        if (args[0].contains("gen"))
        {
            System.out.println("Generate keys");
            long start = System.nanoTime();
            KeyGen kg = new KeyGen(4096, privateKey, publicKey);
            kg.generateKeys();
            long stop = System.nanoTime();
            System.out.println("Keys are generated with size "+kg.keySize);
            System.out.println("Public exponent is "+kg.keyPair.getPublic().toString());
            RSAPrivateKey r = (RSAPrivateKey) kg.keyPair.getPrivate();
            System.out.println("Private exponent is "+r.getPrivateExponent());
            System.out.println("It took " + (stop-start)/1e9d);
        }
        else if (args[0].contains("enc"))
        {
            System.out.println("Encrypting!");
        }
        else if(args[0].contains("dec"))
        {
            System.out.println("Decrypting!");
            /* Deszyfruj tutaj*/

        } else System.out.println("Undefined command!");
    }
}

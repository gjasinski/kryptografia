package pl.edu.agh;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Main {

    public static final String FILE_NAME = "/home/grzegorz/Pobrane/SymmetricCipher/src/main/resources/plaintext";

    public static void main(String[] args) {
        try {

            CipherMachine machine = new CipherMachine();

            if (args[0].contains("enc")) {
                byte[] bytes = readFile(FILE_NAME);
                System.out.println("Encrypting file!");

                long start = System.nanoTime();
                byte[] encrypted = machine.encrypt(bytes);
                long end = System.nanoTime();
                System.out.println(String.format("enc %d ns", end - start));
                writeFile(encrypted, FILE_NAME);


            } else if (args[0].contains("dec")) {
                byte[] bytes = readFile(FILE_NAME + "-out");
                System.out.println(bytes.length);
                System.out.println("Decrypting file!");

                long start = System.nanoTime();
                byte[] decrypted = machine.decrypt(bytes);
                long end = System.nanoTime();
                System.out.println(String.format("dec %d ns", end - start));
                writeFile(decrypted, FILE_NAME + "-out-decrypted");

            } else {
                System.out.println("Undefined command!");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }


    }

    private static byte[] readFile(String fileName) throws IOException {
        Path fileLocation = Paths.get(fileName);
        return Files.readAllBytes(fileLocation);
    }



    public static void writeFile(byte[] output, String fileName) throws IOException {
        fileName = fileName + "-out";

        try (FileOutputStream fos = new FileOutputStream(fileName)) {
            fos.write(output);
        }
    }
}

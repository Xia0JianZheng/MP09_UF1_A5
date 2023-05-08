import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.util.*;

public class UtilitatsXifrar {
    Scanner sc = new Scanner(System.in);

    public static SecretKey keygenKeyGeneration(int keySize) {
        SecretKey sKey = null;
        if ((keySize == 128) || (keySize == 192) || (keySize == 256)) {
            try {
                KeyGenerator kgen = KeyGenerator.getInstance("AES");
                kgen.init(keySize);
                sKey = kgen.generateKey();

            } catch (NoSuchAlgorithmException ex) {
                System.err.println("Generador no disponible.");
            }
        }
        return sKey;
    }

    public static SecretKey passwordKeyGeneration(String text, int keySize) {
        SecretKey sKey = null;
        if ((keySize == 128) || (keySize == 192) || (keySize == 256)) {
            try {
                byte[] data = text.getBytes("UTF-8");
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] hash = md.digest(data);
                byte[] key = Arrays.copyOf(hash, keySize / 8);
                sKey = new SecretKeySpec(key, "AES");
            } catch (Exception ex) {
                System.err.println("Error generant la clau:" + ex);
            }
        }
        return sKey;
    }

    public static KeyPair randomGenerate(int len) {
        KeyPair keys = null;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(len);
            keys = keyGen.genKeyPair();
        } catch (Exception ex) {
            System.err.println("Generador no disponible.");
        }
        return keys;
    }

    public static byte[] encryptData(PublicKey sKey, byte[] data) {
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "SunJCE");
            cipher.init(Cipher.ENCRYPT_MODE, sKey);
            encryptedData = cipher.doFinal(data);
        } catch (Exception ex) {
            System.err.println("Error xifrant les dades: " + ex);
        }
        return encryptedData;
    }

    public static byte[] decryptData(PrivateKey sKey, byte[] data) {
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "SunJCE");
            cipher.init(Cipher.DECRYPT_MODE, sKey);
            encryptedData = cipher.doFinal(data);
        } catch (Exception ex) {
            System.err.println("Error dexifrant les dades: " + ex);
        }
        return encryptedData;
    }

    public static KeyStore loadKeyStore(String ksFile, String ksPwd) throws Exception {
        KeyStore ks = KeyStore.getInstance("JCEKS");
        File f = new File (ksFile);
        if (f.isFile()) {
            FileInputStream in = new FileInputStream (f);
            ks.load(in, ksPwd.toCharArray());
        }
        return ks;
    }

    public static void keyPairEncryptDecryptMsg(){
        int keySize = 1024;
        Scanner sc = new Scanner(System.in);
        KeyPair clave = UtilitatsXifrar.randomGenerate(keySize);

        System.out.println(clave.getPublic());

        System.out.println("Introduce el mensaje que quieres cifrar :");
        String msg = sc.nextLine();

        byte[] msgEncrypt = UtilitatsXifrar.encryptData(clave.getPublic(),msg.getBytes());

        System.out.println("Mensaje Cifrado : " + new String(msgEncrypt));

        byte[] msgDecrypt = UtilitatsXifrar.decryptData(clave.getPrivate(),msgEncrypt);

        System.out.println("Mensaje Descifrado : " + new String(msgDecrypt));

        System.out.println("Clave Publico");
        System.out.println(clave.getPublic());
        System.out.println("Clave Privado");
        System.out.println(clave.getPrivate());
    }

    public static void showInfoKeyStore() {
        Scanner sc = new Scanner(System.in);
        System.out.println("Introduce la ruta del keyStore");
        String ruta = sc.nextLine();
        System.out.println("Introduce la contraseña del keyStore");
        String pass = sc.nextLine();
        try{
            KeyStore keyStore = UtilitatsXifrar.loadKeyStore(ruta,pass);

            System.out.println("El tipo de keyStore :");
            System.out.println(keyStore.getType());

            System.out.println("El tamaño de del keyStore");
            System.out.println(keyStore.size());

            Enumeration<String> aliases = keyStore.aliases();
            System.out.println("Alias de las claves:");
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                System.out.println(alias);
            }

            String alias = "mykeypair";
            Certificate cert = keyStore.getCertificate(alias);
            System.out.println("Certificado de la clave " + alias + ":");
            System.out.println(cert);


            Key key = keyStore.getKey(alias, "password".toCharArray());
            String algorithm = key.getAlgorithm();
            System.out.println("Algorismo de la clava " + alias + ": " + algorithm);

        }catch (Exception e){
            e.printStackTrace();
        }

    }

    public static void addSecretKeyToKeyStore() {
        Scanner sc = new Scanner(System.in);
        System.out.println("Introduce la ruta del keyStore");
        String ruta = sc.nextLine();
        System.out.println("Introduce la contraseña del keyStore");
        String pass = sc.nextLine();

        try {
            KeyStore keyStore = UtilitatsXifrar.loadKeyStore(ruta, pass);
            int keySize = 128;
            SecretKey clave = UtilitatsXifrar.keygenKeyGeneration(keySize);

            KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(clave);
            keyStore.setEntry("mykeystore", skEntry, new KeyStore.PasswordProtection(pass.toCharArray()));
            keyStore.store(new FileOutputStream("src/Files/mykeystore.jck"), "password".toCharArray());

        }catch(Exception e){
            e.printStackTrace();
        }



    }

}

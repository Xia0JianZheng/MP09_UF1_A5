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
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
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
        File f = new File(ksFile);
        if (f.isFile()) {
            FileInputStream in = new FileInputStream(f);
            ks.load(in, ksPwd.toCharArray());
        }
        return ks;
    }

    public static void keyPairEncryptDecryptMsg() {
        int keySize = 1024;
        Scanner sc = new Scanner(System.in);
        KeyPair clave = UtilitatsXifrar.randomGenerate(keySize);

        System.out.println(clave.getPublic());

        System.out.println("Introduce el mensaje que quieres cifrar :");
        String msg = sc.nextLine();

        byte[] msgEncrypt = UtilitatsXifrar.encryptData(clave.getPublic(), msg.getBytes());

        System.out.println("Mensaje Cifrado : " + new String(msgEncrypt));

        byte[] msgDecrypt = UtilitatsXifrar.decryptData(clave.getPrivate(), msgEncrypt);

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
        try {
            KeyStore keyStore = UtilitatsXifrar.loadKeyStore(ruta, pass);

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

        } catch (Exception e) {
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

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void getPublicKeyCert() throws FileNotFoundException, CertificateException {
        Scanner sc = new Scanner(System.in);
        System.out.println("Introduce la ruta del certificado");
        String ruta = sc.nextLine();

        PublicKey publicKey = getPublicKey(ruta);
        System.out.println("Algorithm: " + publicKey.getAlgorithm());
        System.out.println("Format: " + publicKey.getFormat());
        System.out.println("Key Info: " + new String(publicKey.toString()));

    }

    public static PublicKey getPublicKey(String fitxer) throws CertificateException, FileNotFoundException {
        FileInputStream fis = new FileInputStream(new File(fitxer));
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(fis);
        return cert.getPublicKey();
    }

    public static PublicKey getPublicKeyAsimetricKey() throws Exception {
        Scanner sc = new Scanner(System.in);

        System.out.println("introduce la ruta del keyStore");
        String ruta = sc.nextLine();

        System.out.println("Introduce el alias");
        String alias = sc.nextLine();

        System.out.println("Introduce el password del keyStore");
        String ksPassword = sc.nextLine();

        System.out.println("Introduce el password de la clave");
        String keypass = sc.nextLine();

        KeyStore ks = KeyStore.getInstance("JCEKS");

        try (FileInputStream fis = new FileInputStream(ruta)) {
            ks.load(fis, ksPassword.toCharArray());
        }

        PublicKey publicKey = getPublicKey(ks, alias, keypass);
        System.out.println("Public key algorithm: " + publicKey.getAlgorithm());
        System.out.println("Public key format: " + publicKey.getFormat());
        System.out.println("Public key: " + publicKey);
        return publicKey;
    }

    public static PublicKey getPublicKey(KeyStore ks, String alias, String pw) throws Exception {
        Key key = ks.getKey(alias, pw.toCharArray());
        if (key instanceof PublicKey) {
            return (PublicKey) key;
        }
        Certificate cert = ks.getCertificate(alias);
        return cert.getPublicKey();
    }


    public static byte[] getSignature() throws NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException, FileNotFoundException, UnrecoverableKeyException {
        Scanner sc = new Scanner(System.in);

        System.out.println("introduce la ruta del keyStore");
        String ruta = sc.nextLine();

        System.out.println("Introduce el alias");
        String alias = sc.nextLine();

        System.out.println("Introduce el password del keyStore");
        String ksPassword = sc.nextLine();

        System.out.println("Introduce el password de la clave");
        String keyPassword = sc.nextLine();

        System.out.println("Introduce los datos");
        String data = sc.nextLine();

        KeyStore ks = KeyStore.getInstance("JCEKS");
        try (InputStream is = new FileInputStream(ruta)) {
            ks.load(is, ksPassword.toCharArray());
        } catch (CertificateException | IOException e) {
            throw new RuntimeException(e);
        }

        PrivateKey privateKey = (PrivateKey) ks.getKey(alias, keyPassword.toCharArray());

        byte[] signature = signData(data.getBytes(), privateKey);
        System.out.println(new String (signature));
        return signature;
    }


    public static byte[] signData(byte[] data, PrivateKey priv) {
        byte[] signature = null;

        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initSign(priv);
            signer.update(data);
            signature = signer.sign();
        } catch (Exception ex) {
            System.err.println("Error signant les dades: " + ex);
        }
        return signature;
    }

    public static boolean validateSignature(byte[] data, byte[] signature, PublicKey pub) {
        boolean isValid = false;
        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initVerify(pub);
            signer.update(data);
            isValid = signer.verify(signature);
        } catch (Exception ex) {
            System.err.println("Error validant les dades: " + ex);
        }
        return isValid;
    }

    public static void validateinfo() throws Exception {
        Scanner sc = new Scanner(System.in);
        System.out.println("Introduce el data");
    String data = sc.nextLine();
        System.out.println(validateSignature(data.getBytes(), getSignature(),getPublicKeyAsimetricKey()));
    }

    public static byte[][] encryptWrappedData(byte[] data, PublicKey pub) {
        byte[][] encWrappedData = new byte[2][];
        // Generació de clau simètrica
        try {
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128);
            SecretKey sKey = kgen.generateKey();

            // Dades a xifrar
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, sKey);
            byte[] encMsg = cipher.doFinal(data);

            // Algorisme de xifrat asimetric i clau pública de B
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.WRAP_MODE, pub);

            // Algorisme de xifrat simètric i clau xifrada
            byte[] encKey = cipher.wrap(sKey);

            // Dades xifrades
            encWrappedData[0] = encMsg;
            encWrappedData[1] = encKey;
        } catch (Exception  ex) {
            System.err.println("Ha succeït un error xifrant: " + ex);
        }
        return encWrappedData;
    }

    public static byte[] decryptWrappedData(byte[][] encWrappedData, PrivateKey priv) {
        try {
            // Algorisme de xifrat asimetric:
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            // Desxifrar amb clau privada de B
            cipher.init(Cipher.UNWRAP_MODE, priv);
            SecretKey sKey = (SecretKey) cipher.unwrap(encWrappedData[1], "AES", Cipher.SECRET_KEY);
            // Algorisme de xifrat simètric
            cipher = Cipher.getInstance("AES");
            // Desxifrar les dades xifrades amb la clau simètrica
            cipher.init(Cipher.DECRYPT_MODE, sKey);
            byte[] decMsg = cipher.doFinal(encWrappedData[0]);
            // Dades desxifrades
            return decMsg;
        } catch (Exception ex) {
            System.err.println("Ha succeït un error desxifrant: " + ex);
            return null;
        }
    }

    public static void encryptDecryptWrappedData(){
        try{
            KeyPair keyPairA = randomGenerate(1024);
            PublicKey publicKeyA = keyPairA.getPublic();
            PrivateKey privateKeyA = keyPairA.getPrivate();

            KeyPair keyPairB = randomGenerate(1024);
            PublicKey publicKeyB = keyPairB.getPublic();
            PrivateKey privateKeyB = keyPairB.getPrivate();

            String message = "mensaje secreto";

            byte[][] encWrappedData = encryptWrappedData(message.getBytes(), publicKeyB);
            System.out.println("Mensaje Cifrado : ");
            System.out.println(Arrays.toString(encWrappedData));

            byte[] decMsg = decryptWrappedData(encWrappedData, privateKeyB);
            System.out.println("Mensaje Descifrado : ");
            System.out.println(new String(decMsg));
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}

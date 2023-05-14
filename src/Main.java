import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws Exception {
        UtilitatsXifrar utilitatsXifrar = new UtilitatsXifrar();
        Scanner sc = new Scanner(System.in);
        while (true) {
            int opt;
            System.out.println("Introduce la operacion que quieres realizar :");
            System.out.println("1. Cifrar y Descifrar mensaje");
            System.out.println("2. Mostrar informacion del keyStore");
            System.out.println("3. Añadir secretKey a keystore");
            System.out.println("4. Mostrar public key de un certificato");
            System.out.println("5. Mostrar public key de un asimetrickey");
            System.out.println("6. Mostrar signatura");
            System.out.println("7. Validar una informacion");
            System.out.println("8. Cifrar y Descifrar Wrapped Data");
            System.out.println("9. Salir");
            opt = sc.nextInt();
            switch (opt){
                case 1:
                    UtilitatsXifrar.keyPairEncryptDecryptMsg();
                    break;
                case 2:
                    UtilitatsXifrar.showInfoKeyStore();
                    break;
                case 3:
                    UtilitatsXifrar.addSecretKeyToKeyStore();
                case 4:
                    UtilitatsXifrar.getPublicKeyCert();
                    break;
                case 5:
                    UtilitatsXifrar.getPublicKeyAsimetricKey();
                    break;
                case 6:
                    UtilitatsXifrar.getSignature();
                    break;
                case 7:
                    UtilitatsXifrar.validateinfo();
                    break;
                case 8:
                    UtilitatsXifrar.encryptDecryptWrappedData();
                    break;
                case 9:
                    System.exit(0);
                default:
                    System.out.println("Opcion no valida");
            }
        }
    }
}
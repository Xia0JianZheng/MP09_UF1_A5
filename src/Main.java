import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        UtilitatsXifrar utilitatsXifrar = new UtilitatsXifrar();
        Scanner sc = new Scanner(System.in);
        while (true) {
            int opt;
            System.out.println("Introduce la operacion que quieres realizar :");
            System.out.println("1. Cifrar y Descifrar mensaje");
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
                    break;
            }
        }
    }
}
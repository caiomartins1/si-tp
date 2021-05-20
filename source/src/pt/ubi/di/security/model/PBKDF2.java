package pt.ubi.di.security.model;

import pt.ubi.di.security.model.SecurityUtil;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;


public class PBKDF2 {

    /**
     * @param password   String password from which a derived key is generated
     * @param iterations int number of iterations (recommended values: 4096, 2000, 10000, 5000 100000)
     * @param keyLength  int length of the generated key in bits (recommended: 512)
     * @return String representation of derived key generated
     * <p>
     * Examples of pseudorandom function for PBKDF2 include
     * HMAC with SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
     */
    public static String hashPassword(String algorithm, String password, int iterations, int keyLength) {

        String salt = "123456789abcdef123456789abcdef"; // String cryptographic salt (recommended: at least 64 bits)
        char[] passwordChars = password.toCharArray();
        byte[] saltBytes = salt.getBytes();

        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHMAC" + algorithm);
            PBEKeySpec spec = new PBEKeySpec(passwordChars, saltBytes, iterations, keyLength);
            SecretKey key = skf.generateSecret(spec);
            byte[] res = key.getEncoded();


            return SecurityUtil.byteArrayToHex(res);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println("The provided algorithm is not valid");
            return "";
        }
    }


    /**
     * Handles the params given by the user
     * @param args array of strings with flags and its respective values
     * In case of only providing the password, this method sets default values for:
     *             - Algorithm (SHA-1)
     *             - Iterations (1000)
     *             - Key Length (512 bits)
     */
    public static void handlePBKDFParams(String[] args) {
        String algo = "sha1";
        String pass = "";
        int iter = 1000;
        int keyLength = 512;

        for (int i = 1; i < args.length; i++) {
            if (args[i].equals("-a")) {
                algo = args[i + 1];
            }
            if (args[i].equals("-p")) {
                pass = args[i + 1];
            }
            if (args[i].equals("-i")) {
                iter = Integer.parseInt(args[i + 1]);
            }
            if (args[i].equals("-l")) {
                keyLength = Integer.parseInt(args[i + 1]);
            }
        }

        if (pass.equals("")) {
            System.out.println("Must provide a password -> check -help");
            return;
        }

        System.out.println((hashPassword(algo, pass, iter, keyLength)));
    }

}

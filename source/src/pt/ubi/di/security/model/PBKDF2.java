package pt.ubi.di.security.model;

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
            System.out.println("The provided algorithm is not valid, check -help to more details");
            return "";
        }
    }


    /**
     * Handles the params given by the user
     *
     * @param args array of strings with flags and its respective values
     *             In case of only providing the password, this method sets default values for:
     *             - Algorithm (SHA-1)
     *             - Iterations (1000)
     *             - Key Length (512 bits)
     */
    public static void handlePBKDFParams(String[] args) {
        String algo = "sha1";
        String pass = "";
        int iter = 1000;
        int keyLength = 512;

        int helpIndex = SecurityUtil.lookOptions(args, new String[]{"-help", "-h", "--help"});
        if (helpIndex != -1) {
            System.out.println("Help menu");
            return;
        }

        int algoIndex = SecurityUtil.lookOptions(args, new String[]{"-a", "-algo", "--algo"});
        if (algoIndex != -1) {
            algo = args[algoIndex + 1];
        }

        int passwordIndex = SecurityUtil.lookOptions(args, new String[]{"-p", "-password", "--password"});
        if (passwordIndex != -1) {
            pass = args[passwordIndex + 1];
        } else {
            System.out.println("Must provide a password, check -help for more details");
            return;
        }

        int iterIndex = SecurityUtil.lookOptions(args, new String[]{"-i", "-iter", "--iter"});
        if (iterIndex != -1) {
            try {
                iter = Integer.parseInt(args[iterIndex + 1]);
            } catch (Exception e) {
                System.out.println("Iteration must be a number, using default value (1000)");
            }
        }

        int lengthIndex = SecurityUtil.lookOptions(args, new String[]{"-l", "-length", "--length"});
        if (lengthIndex != -1) {
            try {
                keyLength = Integer.parseInt(args[lengthIndex + 1]);
            } catch (Exception e) {
                System.out.println("Length must be a number, using default value (512 bits)");
            }
        }
        System.out.println((hashPassword(algo, pass, iter, keyLength)));
    }

}

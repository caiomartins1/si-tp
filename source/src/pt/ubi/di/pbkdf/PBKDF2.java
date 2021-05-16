package pt.ubi.di.pbkdf;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

//TODO: Maybe implement from scratch?
//TODO: Choose different hash functions 
public class PBKDF2 {
    public static void main(String[] args) {

        // Example of usage (Java chars are 2 bytes sized)
        System.out.println(hashPassword("sha1", "password", "1234", 10000, 512));
    }

    /**
     * @param byteArr byte array to be converted to a hex String
     * @return String representation of hex value.
     * <p>
     * source: https://howtodoinjava.com/java/java-security/how-to-generate-secure-password-hash-md5-sha-pbkdf2-bcrypt-examples/
     */
    private static String byteArrayToHex(byte[] byteArr) {
        BigInteger value = new BigInteger(1, byteArr);
        String hex = value.toString(16);

        int paddingLength = (byteArr.length * 2) - hex.length();
        if (paddingLength > 0) {
            return String.format("%0" + paddingLength + "d", 0) + hex;
        } else {
            return hex;
        }
    }


    /**
     * @param password   String password from which a derived key is generated
     * @param salt       String cryptographic salt (recommended: at least 64 bits)
     * @param iterations int number of iterations (recommended values: 4096, 2000, 10000, 5000 100000)
     * @param keyLength  int length of the generated key in bits (recommended: 512)
     * @return String representation of derived key generated
     * <p>
     *    Examples of pseudorandom function for PBKDF2 include
     *    HMAC with SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and
     *    SHA-512/256.
     */
    public static String hashPassword(String algorithm, String password, String salt, int iterations, int keyLength) {

        char[] passwordChars = password.toCharArray();
        byte[] saltBytes = salt.getBytes();

        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHMAC" + algorithm);
            PBEKeySpec spec = new PBEKeySpec(passwordChars, saltBytes, iterations, keyLength);
            SecretKey key = skf.generateSecret(spec);
            byte[] res = key.getEncoded();

            return byteArrayToHex(res);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println("The provided algorithm is not valid");
            return "";
        }
    }
}
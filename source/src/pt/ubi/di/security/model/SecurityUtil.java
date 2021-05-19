package pt.ubi.di.security.model;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.sound.midi.Soundbank;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.HashSet;
import java.util.Random;

/**
 * TODO need to maybe create a way to generate safe primes
 * secureRandomGenerator
 *  //byte[] bytes = new byte[20];
 *  //secureRandomGenerator.nextBytes(bytes);
 */
public class SecurityUtil {

    static SecureRandom secureRandomGenerator = new SecureRandom(); // uses SHA1PRNG
    static Random random = new Random();
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    private static final int HASHSIZE=20; // size of the hash produced by SHA1

    /**
     * Generates a prime number
     * @param bitLength int - amount of bits desired
     * @param verbose boolean - print messages
     * @return BigInteger - (probably) prime number
     */
    public static BigInteger generatePrime(int bitLength, boolean verbose) {
        BigInteger prime = BigInteger.probablePrime(bitLength,random/*TODO make sure its not fucking anything serious*/);
        if (verbose)
            System.out.println("--->Random prime(" +bitLength+ "bits)(p): "+prime.toString());
        return prime;
    }

    /**
     * Generates a safe prime number<p> TODO:complete description
     * Harder to attack -> Takes longer to generate
     * @param bitLength int - amount of bits desired
     * @param verbose  boolean - print messages
     * @return BigInteger (probably) prime number
     */
    public static BigInteger generateSafePrime(int bitLength, boolean verbose) {
        boolean flag;
        do {
            if (verbose)
                System.out.print(".");
            BigInteger prime = generatePrime(bitLength,false);
            if (verbose)
                System.out.print("*");
            flag = checkIfSafePrime(prime, 1,false);
            if (verbose)
                System.out.print("+");
            if (flag) {
                return prime;
            }
        } while (true);
    }

    /**
     * Generate a random BigInteger by giving a maxValue<p>
     *     0<=random<maxValue
     * Uses java.util.Random
     * @param maxValue BigInteger - max number
     * @param verbose boolean - print messages
     * @return BigInteger - random number BigInteger
     */
    public static BigInteger generateNumber(BigInteger maxValue, boolean verbose) {
        BigInteger number;
        do {
            number = new BigInteger(maxValue.bitLength(), random/*TODO make sure its not fucking anything serious*/);
        } while (number.compareTo(maxValue) >= 0);
        if (verbose)
            System.out.println("--->Random number: "+number.toString());
        return number;
    }

    /**
     * Generate a random number in byte array format
     * @param byteSize - amount of bytes wanted
     * @return byte[] - natural number in byte array format
     */
    public static byte[] generateNumber(int byteSize) {
        byte[] bytesArray = new byte[byteSize];
        for (int i=0;i<byteSize;i++) {
            byte[] tmp = new byte[1];
            secureRandomGenerator.nextBytes(tmp);
            if ((int)tmp[0]<0) {
                tmp[0] += 128;
            }
            bytesArray[i]=tmp[0];
        }
        return bytesArray;
    }

    /**
     * Function to check if a given value is a prime or not
     * @param value BigInteger - value to test if prime
     * @param verbose boolean - print messages
     * @return boolean - true if value is prime, false if value is not prime
     */
    public static boolean checkIfPrime(BigInteger value, boolean verbose) {
        if (value.isProbablePrime(5)) { //kinda useless
            if (verbose)
                System.out.println("--->Value: " + value + "\n    is a prime.");
            return true;
        }
        if (verbose)
            System.out.println("--->Value: " + value + "\n    is not a prime.");
        return false;
    }

    /**
     * TODO: check
     * Function to check if a given value is a safe prime or not - NOT AS SLOW<p>
     * provides 2 different methods
     * @param value BigInteger - value to test if it is a safe prime
     * @param verbose boolean - print messages
     * @return boolean true if value is a safe prime, false if value is not a safe prime
     */
    public static boolean checkIfSafePrime(BigInteger value, int method, boolean verbose) {
        BigInteger result;
        if (method == 1) {
            result = value.subtract(BigInteger.ONE).divide(BigInteger.TWO);
        }
        else {
            result = value.multiply(BigInteger.TWO).add(BigInteger.ONE);
        }
        if (checkIfPrime(result,verbose)) {
            if (verbose)
                System.out.println("--->Value: " + value + "\n    is a safe prime.");
            return true;
        }
        if (verbose)
            System.out.println("--->Value: " + value + "\n    is not a safe prime.");
        return false;
    }

    /**
     * Function to find prime factors of a prime number, used to find a generator, Alternative Version, LESS time consuming<p>
     * It finds one or two prime factors only!!!!
     * TODO: Chance it might not work everytime?
     * @param storage HashSet<BigInteger> - hash storage
     * @param value BigInteger - prime to look for factors for
     * @param verbose boolean - print messages
     */
    private static void findPrimeFactors(HashSet<BigInteger> storage, BigInteger value, boolean verbose) {
        boolean flag = false;
        int count = 0;
        int arbitraryNumber = 1;
        while (value.mod(BigInteger.TWO).compareTo(BigInteger.ZERO) == 0) {//if value mod 2 == 0
            storage.add(BigInteger.TWO);
            value = value.divide(BigInteger.TWO);
        }
        for (BigInteger i = BigInteger.valueOf(3);i.compareTo(value.sqrt())<=0;i=i.add(BigInteger.TWO)) {
            if (flag) {
                break;
            }
            if (i.isProbablePrime(5)) {//if value mod i == 0
                if (verbose)
                    System.out.println("--->Found prime factor Alt: " + i);
                storage.add(i);
                value = value.divide(i);
                if (count>=arbitraryNumber) {
                    if (verbose)
                        System.out.println("--->Finishing finding prime factors.");
                    flag = true;
                    break;
                }
                count++;
            }
        }
        if (value.compareTo(BigInteger.TWO)>0) {
            storage.add(value);
        }
    }

    /**
     * For Diffie-Hellman Zp*={1,2,....,p-1} theres a value g that for all g^0, g^1, .... g^(p-1) <p>
     * generates all Zp*, its always possible to find at least one g for Z*p <p><p>
     *
     * For now not confirming if they are safe primes so that (p-1)/2 is also a prime (allowing g=2) <p><p>
     *
     * PS: lets never do this again
     *
     * TODO IMPORTANT!!!!!!!: maybe be able to optimize
     * TODO Need to format function
     *
     * @param p BigInteger - assume its prime
     * @param verbose boolean - print messages
     * @return BigInteger - generator
     */
    public static BigInteger findGenerator(BigInteger p, boolean verbose) {
        HashSet<BigInteger> storage = new HashSet<>();
        BigInteger phi = p.subtract(BigInteger.ONE);
        BigInteger result;

        findPrimeFactors(storage,phi,verbose);

        if (verbose)
            System.out.println("--->Finished finding prime factors.");

        for (BigInteger r = BigInteger.TWO;r.compareTo(phi)<=0;r=r.add(BigInteger.ONE)) {
            boolean flag = false;
            for (BigInteger value : storage) {
                result=(r.modPow((phi.divide(value)),p));
                if (result.compareTo(BigInteger.ONE)==0) {
                    flag = true;
                    break;
                }
            }
            if (!flag) {
                if (verbose)
                    System.out.println("--->Smallest generator g found: "+r.toString());
                return r;
            }
        }
        if (verbose)
            System.out.println("--->Could not find a suitable generator :(");
        return BigInteger.ZERO;
    }

    /**
     * @param byteArr byte array to be converted to a hex String
     * @return String representation of hex value.
     * <p>
     * source: https://howtodoinjava.com/java/java-security/how-to-generate-secure-password-hash-md5-sha-pbkdf2-bcrypt-examples/
     */
    public static String byteArrayToHex(byte[] byteArr) {
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
     * Transform a byte array to String -> UTF_8
     * @param byteArray byte [] - byte array to transform
     * @return String - return the byte array equivalent in string format UTF8
     */
    public static String byteArrayToString(byte[] byteArray) {
        return new String(byteArray,StandardCharsets.UTF_8);
    }

    public static String byteArrayToStringPKCS5(byte[] byteArray) {
        return new String(byteArray,StandardCharsets.UTF_8);
    }

    /**
     * Function to create a hash of a message<p>
     * md = MessageDigest.getInstance(algo);<p>
     * md.update(message);<p>
     * md.digest();
     * @param algo String - String of algorithm to use
     * @param message byte[] - byte array of message to digest
     * @return byte[] - array of bytes of the message digest (hash)
     */
    public static byte[] hash(String algo,byte[] message) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance(algo);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        assert md != null;
        md.update(message);
        return md.digest();
    }

    /**
     * Function to compare hashes and check if they are equal
     * @param hash1 byte[] - byte array of first hash
     * @param hash2 byte[] - byte array of second hash
     * @return boolean - true if they are equal false if not
     */
    public static boolean checkHash(byte[] hash1,byte[] hash2) {
        return MessageDigest.isEqual(hash1,hash2);
    }

    /**
     * Function to create a hash of a message<p>
     * md = MessageDigest.getInstance(algo);<p>
     * md.update(message);<p>
     * md.digest();
     * @param algo String - String of algorithm to use
     * @param message String - String of message to digest
     * @return byte[] - array of bytes of the message digest (hash)
     */
    public static byte[] Hash(String algo,String message) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance(algo);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        assert md != null;
        md.update(message.getBytes());
        return md.digest();
    }

    /**
     * Convert an int number to its byte[] representation
     * @param number int - number to convert
     * @return byte[] - array byte representation of the int number
     */
    public static byte[] intToByte(int number) {
        return BigInteger.valueOf(number).toByteArray();
    }

    /**
     * Convert an byte[] number to its int representation
     * @param number byte[] - number to convert
     * @return int - int representation of the byte[] number
     */
    public static int byteToInt(byte[] number) {
        return new BigInteger(number).intValue();
    }

    //-------------------------------------------------------------------------------------------------------------------
    private static final int BOCK_SIZE = 16;
    /**
     *
     * @param message
     * @param key
     * @return
     */
    public static byte[] encryptSecurity(byte[] message,byte[] key) {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = generateIv();

        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] cipherBytes = cipher.doFinal(message);
            byte[] finalCipher = new byte[cipherBytes.length+ivParameterSpec.getIV().length];
            System.arraycopy(ivParameterSpec.getIV(),0,finalCipher,0,ivParameterSpec.getIV().length);
            System.arraycopy(cipherBytes,0,finalCipher,ivParameterSpec.getIV().length,cipherBytes.length);
            System.out.println("AES C: "+SecurityUtil.byteArrayToHex(finalCipher));
            System.out.println("IV: "+SecurityUtil.byteArrayToHex(ivParameterSpec.getIV()));
            return finalCipher;
        } catch (Exception e) {
            System.out.println("Error encrypting message (AES): " + e.getMessage());
        }
        return new byte[0];
    }

    /**
     *
     */
    public static byte[] decipherSecurity(byte[] finalCipher,byte[] key) {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(finalCipher,0,BOCK_SIZE);
        System.out.println("AES C: "+SecurityUtil.byteArrayToHex(finalCipher));
        System.out.println("IV: "+SecurityUtil.byteArrayToHex(ivParameterSpec.getIV()));
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            return cipher.doFinal(finalCipher,BOCK_SIZE,finalCipher.length - BOCK_SIZE);
        } catch (Exception e) {
            System.out.println("Error decrypting cipher (AES): " + e.getMessage());
            e.printStackTrace();
        }
        return new byte[0];
    }

    /**
     * Create noise to encrypt message with
     * Example: NOISE(40B): SHA1(key)(20B) | SHA1(SHA1(key))(20B)
     * @param key byte[] - array of bytes to be used to generate noise
     * @param sizeBytes int - size in bytes of the noise
     * @return byte[]- noise in byte array
     */
    private static byte[] createNoise(byte[] key, int sizeBytes) {
        int index = 0;
        int n = sizeBytes /HASHSIZE;
        byte[] prevDigest = SecurityUtil.hash("SHA1",key);
        byte[] noise = new byte[sizeBytes];
        System.arraycopy(prevDigest,0,noise,index,(sizeBytes <HASHSIZE) ? noise.length : prevDigest.length);
        index = prevDigest.length;
        for(int i=1;i<n;i++) {
            byte[] digest = SecurityUtil.hash("SHA1",prevDigest);
            System.arraycopy(digest,0,noise,index,(index <HASHSIZE) ? noise.length : digest.length);
            index += digest.length;
            prevDigest = digest;
        }
        return noise;
    }

    /**
     * One time pad encryption by doing --> message XOR key
     * @param message byte[] - message to encrypt/decipher
     * @param key byte[] - array of bytes to be used to generate noise
     * @param sizeBytes int - size in bytes of the noise
     * @return byte[] of encrypted/decrypted message
     */
    public static byte[] oneTimePadEncrypt(byte[] message, byte[] key, int sizeBytes) {
        byte[] noise = createNoise(key,sizeBytes);
        if (message.length != noise.length) {
            System.out.println("Error Key not same size as message");
            return new byte[0];
        }
        byte[] cipherBytes = new byte[message.length];
        for(int i=0;i<message.length;i++) {
            cipherBytes[i] = (byte) (message[i] ^ noise[i]);
        }
        return cipherBytes;
    }


    public static byte[] hmac(byte[] key) {
        byte[] msd = hash("SHA256", key);
        return  encryptSecurity(msd, key);
    }

    public static boolean hmacCheck(byte[] hmac, byte[] key) {
        byte[] msg = decipherSecurity(hmac, key);
        byte[] msd = hash("SHA256", key);
        return checkHash(msg, msd);
    }

    /**
     * Function to initialize an byte array to be used as iv for AES encryption
     * array size = 16Bytes
     * @return IvParameterSpec - returns the iv in the required state
     */
    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[BOCK_SIZE];
        secureRandomGenerator.nextBytes(iv);
        return new IvParameterSpec(iv);
    }
}
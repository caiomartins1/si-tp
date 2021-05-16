package pt.ubi.di.security.model;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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
            if ((int)tmp[0]<0) {//TODO dafuq does this do
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
     * Convert an array of bytes to hex String
     * @param byteArr byte[] - array of bytes to be converted to a hex String
     * @return String - String representation of hex value.
     * <p>
     * source: https://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java#9855338
     */
    public static String byteArrayToHex(byte[] byteArr) {
        char[] hexChars = new char[byteArr.length * 2];
        for (int j = 0; j < byteArr.length; j++) {
            int v = byteArr[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Transform a byte array to String -> UTF_8
     * @param byteArray byte [] - byte array to transform
     * @return String - return the byte array equivalent in string format UTF8
     */
    public static String byteArrayToString(byte[] byteArray) {
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
    public static byte[] Hash(String algo,byte[] message) {
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
    public static byte[] IntToByte(int number) {
        return BigInteger.valueOf(number).toByteArray();
    }

    /**
     * Convert an byte[] number to its int representation
     * @param number byte[] - number to convert
     * @return int - int representation of the byte[] number
     */
    public static int ByteToInt(byte[] number) {
        return new BigInteger(number).intValue();
    }

    /**
     * Power for BigInteger
     * WARNING probably not a good idea to use it, results are bound to be f*cking crazy
     * @param base base for pow
     * @param exponent exponent for pow
     * @return result of base^exponent
     */
    public static BigInteger powBig(BigInteger base,BigInteger exponent) {
        BigInteger originalBase = base;
        exponent= exponent.subtract(BigInteger.ONE);
        while (exponent.signum() !=0) {
            base = base.multiply(originalBase);
            exponent = exponent.subtract(BigInteger.ONE);
        }
        return base;
    }
}
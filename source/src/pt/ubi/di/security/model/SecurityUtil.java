package pt.ubi.di.security.model;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Random;

/**
 * TODO need to maybe create a way to generate safe primes
 * secureRandomGenerator
 *  //byte[] bytes = new byte[20];
 *  //secureRandomGenerator.nextBytes(bytes);
 */
public class SecurityUtil {

    //TODO should I keep it like this or rethink it
    //static SecureRandom secureRandomGenerator = new SecureRandom();
    static Random random = new Random();

    /**
     * Generates a prime number,TODO: not *truly random* (try to use secureRandom) for seeding
     * @param bitLength amount of bits desired
     * @param verbose print messages
     * @return BigInteger (probably) prime number
     */
    public static BigInteger generatePrime(int bitLength, boolean verbose) {
        BigInteger prime = BigInteger.probablePrime(bitLength,random);
        if (verbose)
            System.out.println("--->Random prime(" +bitLength+ "bits)(p): "+prime.toString());
        return prime;
    }

    /**
     * Generates a safe prime number,TODO: not *truly random* (try to use secureRandom) for seeding
     * Harder to attack Takes longer to generate
     * @param bitLength amount of bits desired
     * @param verbose print messages
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
            flag = checkIfSafePrime(prime, 0,false);
            if (verbose)
                System.out.print(".");
            if (flag) {
                return prime;
            }
        } while (true);
    }

    /**
     * Need to optmize
     * @param maxValue max number
     * @param verbose print messages
     * @return random number
     */
    public static BigInteger generateNumber(BigInteger maxValue, boolean verbose) {
        BigInteger number;
        do {
            number = new BigInteger(maxValue.bitLength(), random);
        } while (number.compareTo(maxValue) >= 0);
        if (verbose)
            System.out.println("--->Random number: "+number.toString());
        return number;
    }

    /**
     * Function to check if a given value is a prime or not
     * @param value value to test if prime
     * @param verbose print messages
     * @return true if value is prime, false if value is not prime
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
     * Function to check if a given value is a safe prime or not - NOT AS SLOW
     * provides 2 different methods
     * @param value value to test if it is a safe prime
     * @param verbose print messages
     * @return true if value is a safe prime, false if value is not a safe prime
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
     * Function to find prime factors of a prime number, used to find a generator, Alternative Version, LESS time consuming
     * It finds one or two prime factors only!!!!
     * Chance it might not work everytime?
     * @param storage hash storage
     * @param value prime to look for factors for
     * @param verbose print messages
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
     * For Diffie-Hellman Zp*={1,2,....,p-1} theres a value g that for all g^0, g^1, .... g^(p-1)
     * generates all Zp*, its always possible to find at least one g for Z*p
     *
     * For now not confirming if they are safe primes so that (p-1)/2 is also a prime (allowing g=2)
     *
     * PS: lets never do this again
     *
     * TODO IMPORTANT!!!!!!!: maybe be able to optimize
     * TODO Need to format function
     *
     * @param p assume its prime
     * @param verbose print messages
     * @return generator
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
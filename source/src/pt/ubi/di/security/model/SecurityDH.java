package pt.ubi.di.security.model;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;

public class SecurityDH{

    private BigInteger x;
    private final BigInteger g;
    private final BigInteger p;
    private BigInteger K;
    private DiffieHellman storeValue;

    /**
     * <p>Constructor to participate in a Diffie-Hellman key exchange
     * Uses already created <i>g</i> and <i>p</i> values
     * then generates a <i>X</i> value by choosing a random <i>x</i> such that 0 < x < p</p>
     * @param g BigInteger - g value
     * @param p BigInteger -p value
     * @param verbose boolean - allow verbose
     */
    public SecurityDH(BigInteger g, BigInteger p,boolean verbose) {
        this.g = g;
        this.p = p;
        generateValues(verbose);
    }

    /**
     * <p>Constructor to start a Diffie-Hellman key exchange
     * Creates a prime number <i>p</i> and a generator <i>g</i>, and
     * then generates a <i>X</i> value by choosing a random <i>x</i> such that 0 < x < p</p>
     * @param bitLength int - amount of bit for the prime number
     * @param verbose boolean - allow verbose
     */
    public SecurityDH(int bitLength,boolean safe,boolean verbose) {
        if(safe)
            p = SecurityUtil.generateSafePrime(bitLength,verbose);
        else
            p = SecurityUtil.generatePrime(bitLength,verbose);
        g = SecurityUtil.findGenerator(p,verbose);
        generateValues(verbose);
    }

    /**
     * Method to generate an <i>X</i> value by choosing a random <i>x</i> such as
     * 0 < x < p
     * @param verbose boolean - allow verbose
     */
    private void generateValues(boolean verbose) {
        x = SecurityUtil.generateNumber(p,verbose);
        BigInteger X = g.modPow(x,p);
        if (verbose) {
            System.out.println(">Values:");
            System.out.println("X = g^x mod p");
            System.out.println("X:" + X);
            System.out.println("x:" + x);
        }
        storeValue = new DiffieHellman(p,g,X);
    }

    /**
     * Generates a k value to be used as a key, uses a given value Y (the X from the participant's operation)
     * Y = Y^x mod p
     * @param Y BigInteger
     */
    public void generateKey(BigInteger Y) {
        K=Y.modPow(x,p);
    }

    public DiffieHellman getStoreValue() {
        return storeValue;
    }

    public byte[] getKBytes() {
        return K.toByteArray();
    }

    /**
     * Method to start a key exchange with whoever is connected, allows different options
     * @param outputStream ObjectOutputStream - output information to send information
     * @param inputStream ObjectInputStream - inputStream to receive information
     * @param options String[] - string array of options for more custom interaction
     * @return byte[] - returns the key in byte array format
     */
    public static byte[] startExchange(ObjectOutputStream outputStream, ObjectInputStream inputStream, String[] options) {
        try {
            System.out.println(">Starting Diffie Hellman key exchange");
            int lengthBit = 1024;
            boolean verbose = false;
            boolean safe = false;
            int index = SecurityUtil.lookOptions(options,"-l");
            if (index!=-1)
                lengthBit = Integer.parseInt(options[index+1]);
            index = SecurityUtil.lookOptions(options,"-v");
            if(index!=-1)
                verbose = true;
            index = SecurityUtil.lookOptions(options,"-s");
            if(index!=-1)
                safe = true;
            SecurityDH factoryDH = new SecurityDH(lengthBit,safe,verbose);
            outputStream.writeObject(factoryDH.getStoreValue());
            DiffieHellman resultDH = (DiffieHellman) inputStream.readObject();
            factoryDH.generateKey(resultDH.getX());
            return factoryDH.getKBytes();
        }
        catch (Exception e) {
            System.out.println("Error on DH key exchange(start): "+e.getMessage());
        }
        return new byte[0];
    }

    /**
     * Method to accept and participate on a key exchange with whoever is connected
     * @param outputStream ObjectOutputStream - output information to send information
     * @param inputStream ObjectInputStream - inputStream to receive information
     * @return byte[] - returns the key in byte array format
     */
    public static byte[] receiveExchange(ObjectOutputStream outputStream, ObjectInputStream inputStream) {
        try {
            System.out.println(">Starting Diffie Hellman key exchange");
            DiffieHellman generatedValues = (DiffieHellman) inputStream.readObject();
            SecurityDH resultDH = new SecurityDH(generatedValues.getG(),generatedValues.getP(),false);
            resultDH.generateValues(false);
            outputStream.writeObject(resultDH.getStoreValue());
            resultDH.generateKey(generatedValues.getX());
            return resultDH.getKBytes();
        }
        catch (Exception e) {
            System.out.println("Error on DH key exchange(receive): "+e.getMessage());
        }
        return new byte[0];
    }

    public static void help() {
        System.out.println(
                "Diffie-Hellman KAP Commands =============================\n" +
                        "-l \033[3mlengthBit\033[0m, length of the prime, default 1024\n" +
                        "-s, generates Sophie Germain Primes (safe primes), takes much longer" +
                        "-v, verbose\n" +
                        "================================================\n"
        );
    }
}

package pt.ubi.di.security.model;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;

/**
 * @author Vitor Neto
 */
public class SecurityDH{

    private BigInteger x;
    private final BigInteger g;
    private final BigInteger p;
    private BigInteger K;
    private DiffieHellman storeValue;
    private final int bitLength;

    /**
     * <p>Constructor to participate in a Diffie-Hellman key exchange
     * Uses already created <i>g</i> and <i>p</i> values
     * then generates a <i>X</i> value by choosing a random <i>x</i> such that 0 < x < p</p>
     * @param g BigInteger - g value
     * @param p BigInteger -p value
     * @param verbose boolean - allow verbose
     */
    public SecurityDH(BigInteger g, BigInteger p, int bitLength,boolean verbose) {
        this.g = g;
        this.p = p;
        this.bitLength = bitLength;
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
        this.bitLength = bitLength;
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
        storeValue = new DiffieHellman(p,g,X,bitLength);
    }

    /**
     * Generates a k value to be used as a key, uses a given value Y (the X from the participant's operation)
     * Y = Y^x mod p
     * @param Y BigInteger
     */
    public void generateKey(BigInteger Y) {
        K = new BigInteger(Y.modPow(x,p).toByteArray(),0,bitLength/8);
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
            int index = SecurityUtil.lookOptions(options, new String[]{"-l","-length","--length"});
            if (index!=-1) {
                try {
                    lengthBit = Integer.parseInt(options[index + 1]);
                }
                catch (Exception e){
                    System.out.println("Error: "+e.getMessage() + " 1024 being used as default.");
                }
            }
            index = SecurityUtil.lookOptions(options,new String[]{"-v","-verbose","--verbose"});
            if(index!=-1)
                verbose = true;
            index = SecurityUtil.lookOptions(options,new String[]{"-s","-safe","--safe"});
            if(index!=-1)
                safe = true;
            SecurityDH factoryDH = new SecurityDH(lengthBit,safe,verbose);
            outputStream.writeBoolean(verbose);
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
            boolean verbose = inputStream.readBoolean();
            DiffieHellman generatedValues = (DiffieHellman) inputStream.readObject();
            SecurityDH resultDH = new SecurityDH(generatedValues.getG(),generatedValues.getP(),generatedValues.getBitLength(),verbose);
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
                """
                        Diffie-Hellman KAP Commands =====================================================
                        -l -length --length \033[3mlengthBit\033[0m, length of the prime, default 1024
                        -s -safe --safe, generates Sophie Germain Primes (safe primes) - takes much longer
                        -v -verbose --verbose, shows verbose
                        =================================================================================
                        """
        );
    }
}

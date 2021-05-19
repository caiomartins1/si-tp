package pt.ubi.di.security.model;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;

public class SecurityDH implements Serializable {

    //TODO setup public/private variables
    //TODO improve DH organization
    private BigInteger X;
    private BigInteger x;
    private BigInteger g;
    private BigInteger p;
    private BigInteger K;

    /**
     *
     * @param g
     * @param p
     * @param verbose
     */
    public SecurityDH(BigInteger g, BigInteger p,boolean verbose) {
        this.g = g;
        this.p = p;
        generateValues(verbose);
    }
    public SecurityDH(int bitLength,boolean verbose) {
        p = SecurityUtil.generatePrime(bitLength,verbose);
        g = SecurityUtil.findGenerator(p,verbose);
        generateValues(verbose);
    }

    /**
     *
     * @param verbose
     */
    public void generateValues(boolean verbose) {
        x = SecurityUtil.generateNumber(p,verbose);
        X = g.modPow(x,p);

        if (verbose)
            System.out.println("X = g^x mod p <->" + X + " = " + g + "^" + x + " mod " + p);
    }

    /**
     *
     * @param bitLength
     * @param x
     * @param verbose
     */
    public void generateValues(int bitLength, BigInteger x, boolean verbose) {
        p = SecurityUtil.generatePrime(bitLength,verbose);
        g = SecurityUtil.findGenerator(p,verbose);

        if( x.compareTo(BigInteger.ZERO) != 0 || x.compareTo(p) >= 0)
            this.x = x;
        else
            this.x = SecurityUtil.generateNumber(p,verbose);

        X = g.modPow(x,p);

        if (verbose)
            System.out.println("X = g^x mod p <->" + X + " = " + g + "^" + x + " mod " + p);
    }

    /**
     *
     * @param Y
     */
    public void generateKey(BigInteger Y) {
        K=Y.modPow(x,p);
        System.out.println("K: " + K);
    }

    public BigInteger getX() {
        return X;
    }

    public BigInteger getG() {
        return g;
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getK() {
        return K;
    }

    /**
     *
     * @param outputStream
     * @param inputStream
     * @param options
     * @return
     */
    public static BigInteger startExchange(ObjectOutputStream outputStream, ObjectInputStream inputStream, String[] options) {
        try {
            System.out.println("_____________Starting Diffie Hellman key exchange_____________");
            SecurityDH factoryDH;
            if (options.length < 2)
                factoryDH = new SecurityDH(128, false);
            else
                factoryDH = new SecurityDH(128, false);
            outputStream.writeObject(factoryDH);
            SecurityDH resultDH = (SecurityDH) inputStream.readObject();
            factoryDH.generateKey(resultDH.getX());
            return factoryDH.getK();
        }
        catch (Exception e) {
            System.out.println("Error on DH key exchange: "+e.getMessage());
        }
        return BigInteger.ZERO;
    }

    /**
     *
     * @param outputStream
     * @param inputStream
     * @return
     */
    public static BigInteger receiveExchange(ObjectOutputStream outputStream, ObjectInputStream inputStream) {
        try {
            System.out.println("_____________Starting Diffie Hellman key exchange_____________");
            SecurityDH a = (SecurityDH) inputStream.readObject();
            SecurityDH b = new SecurityDH(a.getG(),a.getP(),false);
            b.generateValues(false);
            outputStream.writeObject(b);
            b.generateKey(a.getX());
            return b.getK();
        }
        catch (Exception e) {
            System.out.println("Error on DH key exchange(receive): "+e.getMessage());
        }
        return BigInteger.ZERO;
    }
}

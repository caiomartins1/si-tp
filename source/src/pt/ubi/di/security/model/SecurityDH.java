package pt.ubi.di.security.model;

import java.math.BigInteger;

public class SecurityDH {

    //TODO setup public/private variables
    public BigInteger X;
    BigInteger x;
    BigInteger Y;
    BigInteger y;
    BigInteger g;
    BigInteger p;
    BigInteger K;

    public SecurityDH(BigInteger g, BigInteger p) {
        this.g = g;
        this.p = p;
    }
    public SecurityDH(int bitLength,boolean verbose) {
        p = SecurityUtil.generatePrime(bitLength,verbose);
        g = SecurityUtil.findGenerator(p,verbose);
    }

    public void generateValues(boolean verbose) {

        x = SecurityUtil.generateNumber(p,verbose);
        X = g.modPow(x,p);

        System.out.println("X = g^x mod p <->" + X + " = " + g + "^" + x + " mod " + p);
    }

    public void generateValues(int bitLength, BigInteger x, boolean verbose) {
        p = SecurityUtil.generatePrime(bitLength,verbose);
        g = SecurityUtil.findGenerator(p,verbose);

        if( x.compareTo(BigInteger.ZERO) != 0 || x.compareTo(p) >= 0)
            this.x = x;
        else
            this.x = SecurityUtil.generateNumber(p,verbose);

        X = g.modPow(x,p);

        System.out.println("X = g^x mod p <->" + X + " = " + g + "^" + x + " mod " + p);
    }

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
}

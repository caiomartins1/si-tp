package pt.ubi.di.security.model;

import java.io.Serializable;
import java.math.BigInteger;

public class DiffieHellman implements Serializable {
    private final BigInteger X;
    private final BigInteger g;
    private final BigInteger p;
    private final int bitLength;

    public DiffieHellman(BigInteger p, BigInteger g, BigInteger X, int bitLength) {
        this.X = X;
        this.g = g;
        this.p = p;
        this.bitLength = bitLength;
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

    public int getBitLength() {
        return bitLength;
    }
}

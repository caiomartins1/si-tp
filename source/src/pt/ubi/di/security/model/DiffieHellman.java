package pt.ubi.di.security.model;

import java.io.Serializable;
import java.math.BigInteger;

public class DiffieHellman implements Serializable {
    private final BigInteger X;
    private final BigInteger g;
    private final BigInteger p;

    public DiffieHellman(BigInteger p, BigInteger g, BigInteger X) {
        this.X = X;
        this.g = g;
        this.p = p;
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

package pt.ubi.di.security.model;

import java.io.Serializable;
import java.math.BigInteger;

public class RsaKeys implements Serializable {
    private final BigInteger e;
    private final BigInteger d;
    private final BigInteger n;

    /**
     * Constructor for publicKey
     * @param e
     * @param n
     */
    public RsaKeys(BigInteger e, BigInteger n) {
        this.e =e;
        this.n =n;
        this.d = null;
    }

    /**
     * Constructor for privateKey
     * @param d
     * @param n
     * @param v
     */
    public RsaKeys(BigInteger d, BigInteger n,boolean v) {
        this.d =d;
        this.n =n;
        this.e = null;
    }

    public BigInteger getE() {
        return e;
    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getD() {
        return d;
    }
}

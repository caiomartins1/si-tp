package pt.ubi.di.security.model;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * Format: PublicKey(n,e) or PrivateKey(n,d)
 */
public class RsaKeys implements Serializable {
    /**
     * Part of public key
     */
    private final BigInteger e;
    /**
     *Part of private key
     */
    private final BigInteger d;
    /**
     *Part of private and public key (public value)
     */
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

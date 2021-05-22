package pt.ubi.di.security.model;

/**
 * @author Vitor Neto
 */
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
     * e and n joined together in byte array format
     */
    private byte[] publicKey;

    /**
     * d and n joined together in byte array format
     */
    private byte[] privateKey;

    /**
     * Constructor for publicKey
     * @param e
     * @param n
     */
    public RsaKeys(BigInteger e, BigInteger n) {
        this.e =e;
        this.n =n;
        this.d = null;
        privateKey = null;
        transformPublicKeyToByte();
    }

    /**
     * Constructor for private and public key
     * @param d
     * @param n
     * @param e
     */
    public RsaKeys(BigInteger e,BigInteger d, BigInteger n) {
        this.d =d;
        this.n =n;
        this.e = e;
        transformPrivateKeyToByte();
        transformPublicKeyToByte();
    }

    private void transformPublicKeyToByte() {
        publicKey = new byte[n.toByteArray().length+e.toByteArray().length];
        System.arraycopy(n.toByteArray(),0,publicKey,0,n.toByteArray().length);
        System.arraycopy(e.toByteArray(),0,publicKey,n.toByteArray().length,e.toByteArray().length);
    }

    private void transformPrivateKeyToByte() {
        privateKey = new byte[n.toByteArray().length+d.toByteArray().length];
        System.arraycopy(n.toByteArray(),0,privateKey,0,n.toByteArray().length);
        System.arraycopy(d.toByteArray(),0,privateKey,n.toByteArray().length,d.toByteArray().length);
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public byte[] getPrivateKey() {
        return privateKey;
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

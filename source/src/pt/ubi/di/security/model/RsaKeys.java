package pt.ubi.di.security.model;

/**
 * @author Vitor Neto
 */
import java.io.Serializable;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * Format: PublicKey(n,e) or PrivateKey(n,d)
 */
public class RsaKeys implements Serializable {
    /**
     * Part of public key
     */
    private final BigInteger e;
    private final int eSize;
    /**
     *Part of private key
     */
    private final BigInteger d;
    private final int dSize;
    /**
     *Part of private and public key (public value)
     */
    private final BigInteger n;
    private final int nSize;

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
        eSize = e.toByteArray().length;
        nSize = n.toByteArray().length;
        dSize = -1;
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
        eSize = e.toByteArray().length;
        nSize = n.toByteArray().length;
        dSize = d.toByteArray().length;
        transformPrivateKeyToByte();
        transformPublicKeyToByte();
    }

    private void transformPublicKeyToByte() {
        publicKey = new byte[n.toByteArray().length+e.toByteArray().length];
        System.arraycopy(n.toByteArray(),0,publicKey,0,nSize);
        System.arraycopy(e.toByteArray(),0,publicKey,nSize,eSize);
    }

    private void transformPrivateKeyToByte() {
        privateKey = new byte[n.toByteArray().length+d.toByteArray().length];
        System.arraycopy(n.toByteArray(),0,privateKey,0,nSize);
        System.arraycopy(d.toByteArray(),0,privateKey,nSize,dSize);
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public byte[] getPrivateKey() {
        return privateKey;
    }

    public int getESize() {
        return eSize;
    }

    public int getDSize() {
        return dSize;
    }

    public int getNSize() {
        return nSize;
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

    @Override
    public String toString() {
        return "------------------RSA keys------------------\n" +
                " e=" + e + "\n" +
                " d=" + d + "\n" +
                " n=" + n + "\n" +
                " publicKey=" + SecurityUtil.byteArrayToHex(publicKey) + "\n" +
                " privateKey=" + SecurityUtil.byteArrayToHex(privateKey) + "\n" +
                "-------------------------------------------\n";
    }
}

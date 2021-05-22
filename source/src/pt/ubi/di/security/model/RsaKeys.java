package pt.ubi.di.security.model;

import java.io.Serializable;
import java.math.BigInteger;

/**TODO: DOC
 * Format: PublicKey(n,e) or PrivateKey(n,d)
 * @author Vitor Neto
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
     * algo to be used for message digesting
     */
    private String algo;

    /**
     * prob shouldn't be kept here but oh well
     */
    private static final BigInteger md5MaxSize = BigInteger.valueOf(2).pow(128);
    private static final BigInteger sha1MaxSize = BigInteger.valueOf(2).pow(160);
    private static final BigInteger sha256MaxSize = BigInteger.valueOf(2).pow(256);
    private static final BigInteger sha512MaxSize = BigInteger.valueOf(2).pow(512);

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
        checkAlgoToSign();
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
        checkAlgoToSign();
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

    public void checkAlgoToSign (){
        if (n.compareTo(sha512MaxSize) >= 0)
            algo = "SHA512";
        else if(n.compareTo(sha256MaxSize) >= 0)
            algo = "SHA256";
        else if(n.compareTo(sha1MaxSize) >= 0)
            algo = "SHA1";
        else if(n.compareTo(md5MaxSize) >= 0)
            algo = "MD5";
        else
            algo = "";
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

    public String getAlgo() {
        return algo;
    }

    /**
     * @return true if rsaKey has message digest algorithm setup, else false
     */
    public boolean asAlgo() {
        return !algo.equals("");
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

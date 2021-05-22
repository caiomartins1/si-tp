package pt.ubi.di.security.model;

import java.io.*;
import java.math.BigInteger;

/**
 * Refactor and Doc: @author Vitor Neto
 * PublicKey(n,e)
 * PrivateKey(n,d)
 *  a ≡ b (mod n) -> there is an integer k such that a − b = kn
 *  a mod n = b mod n
 */
public class SecurityRSA {
    /**
     * random prime number of bitLength length
     * keep secret, discardable
     */
    private final BigInteger p;
    /**
     * random prime number of bitLength length
     * kept secret, discardable
     */
    private final BigInteger q;
    /**
     * φ(n) = (p-1)*(q-1)
     * keep secret, discardable
     */
    private BigInteger phi;
    /**
     * λ(n) = lcm(p-1,q-1)
     * keep secret, discardable
     */
    private BigInteger lamb;
    /**
     * n = p*q
     * part of the public key
     */
    private BigInteger n;
    /**
     * 1<e<λ(n) && gcd(e,λ(n))==1
     * (2^16 + 1 = 65,537)
     * part of the public key
     */
    private BigInteger e;
    /**
     * d ≡ e^(-1) (mod λ(n)) <-> d*e ≡ 1 (mod λ(n))
     * part of the private key
     */
    private BigInteger d;

    //PublicKey(n,e)
    //PrivateKey(n,d)

    /**
     * Constructor to start the generation of the key by giving the bitLength size of the prime number
     * TODO
     */
    public SecurityRSA() {
        p = SecurityUtil.generatePrime(1024,false);
        q = SecurityUtil.generatePrime(1024/*TODO needs to have slight difference*/,false);
        generateN();
        generatePhi();
        generateLambda();
        generateE();
        generateD();
    }

    //--------------------------------------------------------------------------------------

    /**
     * @param outputStream
     * @param inputStream
     */
    public static RsaKeys[] startExchange(ObjectOutputStream outputStream, ObjectInputStream inputStream) {
        System.out.println(">Starting RSA key exchange");

        SecurityRSA factoryRSA = new SecurityRSA();
        RsaKeys parKey = new RsaKeys(factoryRSA.getE(),factoryRSA.getD(),factoryRSA.getN());

        try {
            RsaKeys myPublicKey = new RsaKeys(parKey.getE(),parKey.getN());
            outputStream.writeObject(myPublicKey);
            RsaKeys receivedPublicKey = (RsaKeys) inputStream.readObject();
            return new RsaKeys[]{parKey,receivedPublicKey};
        } catch (Exception e) {
            System.out.println("Error writing or reading key: " + e.getMessage());
        }
        return new RsaKeys[]{parKey,null};
    }

    /**
     * @param outputStream
     * @param inputStream
     */
    public static RsaKeys[] receiveExchange(ObjectOutputStream outputStream, ObjectInputStream inputStream) {
        System.out.println(">Starting RSA key exchange");

        SecurityRSA factoryRSA = new SecurityRSA();
        RsaKeys parKey = new RsaKeys(factoryRSA.getE(),factoryRSA.getD(),factoryRSA.getN());

        try {
            RsaKeys myPublicKey = new RsaKeys(factoryRSA.getE(),factoryRSA.getN());
            RsaKeys receivedPublicKey = (RsaKeys) inputStream.readObject();
            outputStream.writeObject(myPublicKey);
            return new RsaKeys[]{parKey,receivedPublicKey};
        } catch (Exception e) {
            System.out.println("Error writing or reading key: " + e.getMessage());
        }
        return new RsaKeys[]{parKey,null};
    }

    //--------------------------------------------------------------------------------------

    /**
     * Method that returns a BigInteger that represents the encrypted hash of the message
     * the public key can be used to decrypt the hash for comparison
     * 1. create hash of the message
     * 2. transform the hash to BigInteger format
     * 3. (hashInteger ^ d) mod n = signature
     * Signs a message hash with a private key, public key can be used to check its integrity
     * @param message byte[] - message to sign, byte[] so it can be anything
     * @param privateKey RsaKeys - RSA private key with D and N values
     * @return BigInteger - number that represents the encrypted hash
     */
    public static BigInteger signWithRSA(byte[] message, RsaKeys privateKey){
        return (new BigInteger(SecurityUtil.hash("SHA-256",message))).modPow(privateKey.getD(),privateKey.getN());
    }

    /**
     * Method to check message signature, make the hash from the message receive, and decrypt
     * the signature received by using the correspond public key
     * @param message byte[] - message to verify signature, byte[] so it can be anything
     * @param signature BigInteger - signature in BigInteger format
     * @param publicKey RsaKeys - rsa public key with E and N values
     * @return boolran returns true if signature is valid false if else
     */
    public static boolean verifySignatureWithRSA(byte[] message, BigInteger signature, RsaKeys publicKey){
        byte[] hashReal = SecurityUtil.hash("SHA-256",message);
        byte[] hashReceived = signature.modPow(publicKey.getE(),publicKey.getN()).toByteArray();
        if(SecurityUtil.checkHash(hashReal,hashReceived)){
            return true;
        }else{
            return false;
        }
    }

    /**
     * Method to encrypt a String message with a public key
     * @param message byte[] - the plain text message
     * @param publicKey RsaKeys - the object with the public key to encrypt
     * @return BigInteger return the cipher in BigInteger format
     */
    public static BigInteger encryptMessage(byte[] message,RsaKeys publicKey){
        return (new BigInteger(message)).modPow(publicKey.getE(),publicKey.getN());
    }

    /**
     * Method to decrypt a cipher, in BigInteger format, with a private key
     * @param cipher BigInteger - cipher wished to be decrypted
     * @param privateKey RsaKeys - rsa private key
     * @return String - clean text message
     */
    public static String decryptMessage(BigInteger cipher,RsaKeys privateKey){
        return SecurityUtil.byteArrayToString(cipher.modPow(privateKey.getD(),privateKey.getE()).toByteArray());
    }

    //--------------------------------------------------------------------

    /**
     * Method to generate n -> n = p*q
     */
    public void generateN() {
        n = p.multiply(q);
    }

    /**
     * Method to generate phi -> φ(n) = (p-1)*(q-1)
     */
    public void generatePhi() {
        phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
    }

    /**
     * Method to generate lambda -> λ(n) = lcm(p-1,q-1)
     * source:<a href="https://www.geeksforgeeks.org/lcm-of-two-large-numbers/">LCM of two large numbers</a>
     */
    public void generateLambda() {
        BigInteger pAux = p.subtract(BigInteger.ONE);
        BigInteger qAux = q.subtract(BigInteger.ONE);
        BigInteger mul = pAux.multiply(qAux);
        BigInteger gcd = pAux.gcd(qAux);
        lamb = mul.divide(gcd);
    }

    /**
     * 1<e<λ(n) && gcd(e,λ(n))==1
     * Or use default value: (2^16 + 1 = 65,537)
     */
    public void generateE() {
        do {
            e = SecurityUtil.generateNumber(lamb,false);
        } while (!(e.gcd(lamb).compareTo(BigInteger.ONE)==0 && e.compareTo(BigInteger.ONE)>0 && e.compareTo(lamb)<0));
    }

    /**
     * Determine d ≡ e^(-1) (mod λ(n)) <-> d*e ≡ 1 (mod λ(n))
     */
    public void generateD() {
        d = e.modInverse(lamb);
    }

    //--------------------------------------------------------------------

    public BigInteger getP(){
        return p;
    }
    public BigInteger getQ(){
        return q;
    }
    public BigInteger getD() {
        return d;
    }
    public BigInteger getE() {
        return e;
    }
    public BigInteger getN(){
        return n;
    }
    public BigInteger getPhi() {
        return phi;
    }
    public BigInteger getLamb() {
        return lamb;
    }

    public static void help() {
        System.out.println(
                """
                        RSA Commands =====================================================
                        -l -length --length \033[3mlengthBit\033[0m, length of the prime, default 1024
                        -v -verbose --verbose, shows verbose
                        =================================================================================
                        """
        );
    }
}
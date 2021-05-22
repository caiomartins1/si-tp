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
    public SecurityRSA(int bitLength, boolean verbose) {
        if(bitLength<1)
            bitLength = 1024;
        p = SecurityUtil.generatePrime(bitLength,verbose);
        q = SecurityUtil.generatePrime(bitLength,verbose);
        generateN();
        generatePhi();
        generateLambda();
        generateE();
        generateD();
    }

    //--------------------------------------------------------------------------------------

    /**
     * @param outputStream ObjectOutputStream - output information to send information
     * @param inputStream ObjectInputStream - inputStream to receive information
     */
    public static RsaKeys[] startExchange(ObjectOutputStream outputStream, ObjectInputStream inputStream, String[] options) {
        System.out.println(">Starting RSA key exchange");
        int lengthBit = 1024;
        boolean verbose = false;
        int index = (SecurityUtil.lookOptions(options,new String[]{"-l","-length","--length"}));
        if (index!=-1) {
            try {
                lengthBit = Integer.parseInt(options[index + 1]);
            }
            catch (Exception e){
                System.out.println("Error: "+e.getMessage() + " 1024 being used as default.");
            }
        }
        if ((SecurityUtil.lookOptions(options,new String[]{"-v","-verbose","--verbose"})) != -1)
            verbose = true;

        SecurityRSA factoryRSA = new SecurityRSA(lengthBit,verbose);

        RsaKeys parKey = new RsaKeys(factoryRSA.getE(),factoryRSA.getD(),factoryRSA.getN());

        try {
            outputStream.writeObject(options);
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
     * @param outputStream ObjectOutputStream - output information to send information
     * @param inputStream ObjectInputStream - inputStream to receive information
     */
    public static RsaKeys[] receiveExchange(ObjectOutputStream outputStream, ObjectInputStream inputStream) {
        System.out.println(">Starting RSA key exchange");
        String[] options = new String[]{};
        try {
            options =(String[]) inputStream.readObject();
        } catch (Exception e) {
            System.out.println("Error receiving options: " + e.getMessage());
        }

        int lengthBit = 1024;
        boolean verbose = false;
        int index = (SecurityUtil.lookOptions(options,new String[]{"-l"}));
        if (index!=-1) {
            try {
                lengthBit = Integer.parseInt(options[index + 1]);
            }
            catch (Exception e){
                System.out.println("Error: "+e.getMessage() + " 1024 being used as default.");
            }
        }
        if ((SecurityUtil.lookOptions(options,new String[]{"-v"})) != -1)
            verbose = true;

        SecurityRSA factoryRSA = new SecurityRSA(lengthBit,verbose);
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

    /**
     *
     * @param outputStream ObjectOutputStream - output information to send information
     * @param inputStream ObjectInputStream - inputStream to receive information
     * @param message byte[] - message to send
     * @param key RsaKeys - key to use for signature
     */
    public static void sendSignature(ObjectOutputStream outputStream, ObjectInputStream inputStream, byte[] message,RsaKeys key) {
        try {
            outputStream.writeObject(signWithRSA(message,key));
        }catch (Exception e) {
            System.out.println("Error sending signature: "+ e.getMessage());
        }
    }

    /**
     *
     * @param outputStream ObjectOutputStream - output information to send information
     * @param inputStream ObjectInputStream - inputStream to receive information
     * @param message byte[] - message to compare
     * @param key RsaKeys - key to use for signature
     * @return boolean - true or false if the signature is valid
     */
    public static boolean receiveSignature(ObjectOutputStream outputStream, ObjectInputStream inputStream, byte[] message, RsaKeys key) {
        try {
            byte[] signature = (byte[]) inputStream.readObject();
            return  verifySignatureWithRSA(message,signature,key);
        }catch (Exception e) {
            System.out.println("Error sending signature: "+ e.getMessage());
        }
        return false;
    }

    //--------------------------------------------------------------------------------------

    /**
     * Method that returns a BigInteger that represents the encrypted hash of the message
     * the public key can be used to decrypt the hash for comparison
     * 1. create hash of the message
     * 2. transform the hash to BigInteger format -> turn positive if negative
     * 3. (hashInteger ^ d) mod n = signature
     * Signs a message hash with a private key, public key can be used to check its integrity
     * @param message byte[] - message to sign, byte[] so it can be anything
     * @param privateKey RsaKeys - RSA private key with D and N values
     * @return byte[] - byte[] that represents the encrypted hash
     */
    public static byte[] signWithRSA(byte[] message, RsaKeys privateKey){
        if(!privateKey.asAlgo()) {
            System.out.println(">Can not apply signature, key is too small");
            return new byte[0];
        }
        BigInteger hashInteger = (new BigInteger(SecurityUtil.hash(privateKey.getAlgo(),message)));
        if(hashInteger.signum()<0)
            hashInteger = hashInteger.negate();
        return hashInteger.modPow(privateKey.getD(),privateKey.getN()).toByteArray();
    }

    /**
     * Method to check message signature, make the hash from the message receive, and decrypt
     * the signature received by using the correspond public key
     * 1. calculate hash of the message received (real hash) -> convert to positive if negative
     * 2. (hashInteger ^ e) mod n = hashInteger
     * 3. decipher hashInteger to hash
     * 4. compare the two hashes
     * @param message byte[] - message to verify signature, byte[] so it can be anything
     * @param signature byte[] - signature in byte[] format
     * @param publicKey RsaKeys - rsa public key with E and N values
     * @return boolean returns true if signature is valid false if else
     */
    public static boolean verifySignatureWithRSA(byte[] message, byte[] signature, RsaKeys publicKey){
        if(!publicKey.asAlgo()) {
            System.out.println("\n>Can not apply signature, key is too small");
            return false;
        }
        byte[] hashReal = SecurityUtil.hash(publicKey.getAlgo(),message);
        BigInteger hashRealInteger = new BigInteger(hashReal);
        if(hashRealInteger.signum()<0) {
            hashRealInteger = hashRealInteger.negate();
            hashReal = hashRealInteger.toByteArray();
        }
        BigInteger hashSignatureInteger = (new BigInteger(signature));

        byte[] hashReceived = hashSignatureInteger.modPow(publicKey.getE(),publicKey.getN()).toByteArray();
        return SecurityUtil.checkHash(hashReal, hashReceived);
    }

    /**
     * Method to encrypt a String message with a public key
     *
     *  0<=message<n
     *
     * @param message byte[] - the plain text message
     * @param publicKey RsaKeys - the object with the public key to encrypt
     * @return byte[] return the cipher in byte[] format
     */
    public static byte[] encryptMessage(byte[] message,RsaKeys publicKey){
        if(new BigInteger(message).compareTo(publicKey.getN())>=0) {
            System.out.println(">Can not encrypt, key is too small.");
            return new byte[0];
        }
        return (new BigInteger(message)).modPow(publicKey.getE(),publicKey.getN()).toByteArray();
    }

    /**
     *
     * 0<=cipher<n
     *
     * Method to decrypt a cipher, in BigInteger format, with a private key
     * @param cipher BigInteger - cipher wished to be decrypted
     * @param privateKey RsaKeys - rsa private key
     * @return byte[] - clean text message in byte array format
     */
    public static byte[] decryptMessage(byte[] cipher,RsaKeys privateKey){
        if(new BigInteger(cipher).compareTo(privateKey.getN())>=0) {
            System.out.println(">Can not decrypt, key is too small.");
            return new byte[0];
        }
        return (new BigInteger(cipher)).modPow(privateKey.getD(),privateKey.getN()).toByteArray();
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
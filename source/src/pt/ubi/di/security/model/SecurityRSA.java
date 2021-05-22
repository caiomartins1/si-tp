package pt.ubi.di.security.model;

import java.io.*;
import java.math.BigInteger;

/**
 * PublicKey(n,e)
 * PrivateKey(n,d)
 *
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
        System.out.println("numbers generated");
        generateN();
        generatePhi();
        generateLambda();
        generateE();
        generateD();
    }

    /**
     * TODO return keys
     * @param outputStream
     * @param inputStream
     */
    public static void startExchange(ObjectOutputStream outputStream, ObjectInputStream inputStream) {
        System.out.println(">Starting RSA key exchange");

        SecurityRSA factoryRSA = new SecurityRSA();
        System.out.println("------------------RSA keys------------------");
        System.out.println("My Public Key: "+ factoryRSA.getE() + "\nMy Private Key: " + factoryRSA.getD());
        System.out.println("-------------------------------------------");

        try {
            RsaKeys publicKey = new RsaKeys(factoryRSA.getE(),factoryRSA.getN());
            outputStream.writeObject(publicKey);
            RsaKeys receivedPublicKey = (RsaKeys) inputStream.readObject();
            System.out.println("Shared public key: " + receivedPublicKey.getE());
        } catch (Exception e) {
            System.out.println("Error writing or reading key: " + e.getMessage());
        }
    }

    /**
     * TODO return keys
     * @param outputStream
     * @param inputStream
     */
    public static void receiveExchange(ObjectOutputStream outputStream, ObjectInputStream inputStream) {
        System.out.println(">Starting RSA key exchange");

        SecurityRSA factoryRSA = new SecurityRSA();
        System.out.println("------------------RSA keys------------------");
        System.out.println("My Public Key: "+ factoryRSA.getE() + "\nMy Private Key: " + factoryRSA.getD());
        System.out.println("-------------------------------------------");

        RsaKeys myPublicKey = new RsaKeys(factoryRSA.getE(),factoryRSA.getN());
        try {
            RsaKeys receivedPublicKey = (RsaKeys) inputStream.readObject();
            outputStream.writeObject(myPublicKey);
            System.out.println("Shared public key: " + receivedPublicKey.getE());
        } catch (Exception e) {
            System.out.println("Error writing or reading key: " + e.getMessage());
        }
    }

    //--------------------------------------------------------------------------------------
    //assinar o hash da mensagem com a sua chave privada
    public BigInteger sign_Message(String plain_message){
        byte[] convert = plain_message.getBytes();
        byte[] hmsg = SecurityUtil.hash("SHA-256",convert);
        //assina com a sua chave privada sobre o valor de hash da mensagem
        BigInteger sign_msg = (new BigInteger(hmsg)).modPow(d,n);
        return sign_msg;
    }
    //verificar a assinatura da mensagem com a chave pública do outro cliente
    public void verify_signature(BigInteger ciphermessage, BigInteger sign_msg, BigInteger pk, BigInteger n){
        String hash = "SHA-256";
        //verificar o hash assinado
        byte[] hash_msg = decript_signed_Message(sign_msg, pk, n);
        //decifrar o hash da mensagem cifrada
        byte[] msg = decript_Message(ciphermessage).getBytes();
        //verificar se é igual ou não
        if(SecurityUtil.checkHash(msg, hash_msg)){
            System.out.println("Is Equal");
        }else{
            System.out.println("Is NOT Equal");
        }
    }
    //decifra com a chave pública do cliente (other one)
    public byte[] decript_signed_Message(BigInteger ciphertext, BigInteger pk, BigInteger n){
        byte[] decrpt = ciphertext.modPow(pk,n).toByteArray();
        //return decrpt - devolve hash da mensagem assinado com a chave privada
        return decrpt;
    }
    //------------------------------------------------------------------------
    //encriptação da mensagem com a chave pública do cliente (other one)
    public BigInteger encript_Message(String plain_message, BigInteger pk, BigInteger n){
        byte[] convert = plain_message.getBytes();
        BigInteger encripted_msg = (new BigInteger(convert)).modPow(pk,n);
        //String encripted_msg = (new BigInteger(plain_message)).modPow(pk,n).toString();
        //devolve o BigInteger da mensagem encriptada com a chave publica
        return encripted_msg;
    }

    //encriptação do hash da mensagem com a chave pública do cliente (other one)
    public BigInteger encript_hashMessage(String plain_message, BigInteger pk, BigInteger n){
        byte[] convert = plain_message.getBytes();
        //determinar o hash da mensagem decifrada
        String hash = "SHA-256";
        byte[] hmsg = SecurityUtil.hash(hash,convert);
        BigInteger encripted_msg = (new BigInteger(hmsg)).modPow(pk,n);
        //String encripted_msg = (new BigInteger(plain_message)).modPow(pk,n).toString();
        //devolve o BigInteger da mensagem encriptada com a chave publica
        return encripted_msg;
    }

    //decifração do criptograma com a sua chave privada
    public String decript_Message(BigInteger ciphertext){
        byte[] decrpt = ciphertext.modPow(d,n).toByteArray();
        String decrpt_msg = new String(decrpt);
        //return String - devolve uma String
        return decrpt_msg;
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
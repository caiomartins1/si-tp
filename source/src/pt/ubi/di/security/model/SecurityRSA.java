package pt.ubi.di.security.model;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;

public class SecurityRSA implements Serializable {
    private BigInteger d, p, q, M;
    BigInteger N, e;
    private int bitLength = 1024;
    private boolean verbose;
    //usado para definir a pk do outro Cliente
    public SecurityRSA(BigInteger e, BigInteger N) {
        this.e = e;
        this.N = N;
    }
    
    public SecurityRSA() {
        //gera 2 números primos
        this.verbose = false;
        p = SecurityUtil.generatePrime(bitLength,verbose);
        q = SecurityUtil.generatePrime(bitLength,verbose);
        generate_N(p,q);
    }

    public void generateValues(int bitLength, boolean verbose) {
        this.verbose = verbose;
        p = SecurityUtil.generatePrime(bitLength,verbose);
        q = SecurityUtil.generatePrime(bitLength,verbose);
        generate_N(p,q);
    }

    public void generate_N(BigInteger p, BigInteger q){
        //Calcula n = p * q
        N = p.multiply(q);
        generate_phi_N();
    }

    public void generate_phi_N(){
        //Calcula a função phi(n) = (p - 1)*(q - 1)
        M = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
    }

    public void calculate_Keys() {
        e = SecurityUtil.generateNumber(M, verbose);
        //pk = (e,N)
        //verifica se phi()/M e "e" são primos entre si
        while (M.gcd(e).intValue() > 1) {
            e = e.add(new BigInteger("1"));
            //se "e" == M então calcula um novo "e"
            if(e == M){
                e = SecurityUtil.generateNumber(M, verbose);
                System.out.println("Big");
            }
        }
        //e*d = 1 mod phi(n)
        // "d" seja inverso de "e"
        d = e.modInverse(M);
        //sk = d
    }

    //--------------------------------------------------------------------------------------
    //assinar o hash da mensagem com a sua chave privada
    public BigInteger sign_Message(String plain_message){
        byte[] convert = plain_message.getBytes();
        String hash = "SHA-256";
        byte[] hmsg = SecurityUtil.hash(hash,convert);
        //assina com a sua chave privada sobre o valor de hash da mensagem
        BigInteger sign_msg = (new BigInteger(hmsg)).modPow(d,N);
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
        byte[] decrpt = ciphertext.modPow(d,N).toByteArray();
        String decrpt_msg = new String(decrpt);
        //return String - devolve uma String
        return decrpt_msg;
    }


    public BigInteger getP(){
        return p;
    }
    public BigInteger getQ(){
        return q;
    }
    public BigInteger getD() {
        return d;
    }
    // public key
    public BigInteger getE() {
        return e;
    }
    public BigInteger getN(){
        return N;
    }
    public void setN(BigInteger N){
        this.N = N;
    }
    public BigInteger getPhi(){
        return M;
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
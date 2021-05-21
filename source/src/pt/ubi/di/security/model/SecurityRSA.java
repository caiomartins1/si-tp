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

    //encriptação da mensagem com a chave pública do cliente (other one)
    public BigInteger encript_Message(String plain_message, BigInteger pk, BigInteger n){
        byte[] convert = plain_message.getBytes();
        BigInteger encripted_msg = (new BigInteger(convert)).modPow(pk,n);
        //String encripted_msg = (new BigInteger(plain_message)).modPow(pk,n).toString();
        //devolve o BigInteger da mensagem encriptada com a chave publica
        return encripted_msg;
    }

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

    //decifração do criptograma com a chave privada do cliente (client one)
    public String decript_Message(BigInteger ciphertext, BigInteger sk, BigInteger n){
        byte[] decrpt = ciphertext.modPow(sk,n).toByteArray();
        String decrpt_msg = new String(decrpt);
        //return String - devolve uma String 
        return decrpt_msg;
    }

    //verificação da integridade de uma mensagem
    public void verify_Integrity(BigInteger ciphertext, BigInteger sk, BigInteger n, String hash, BigInteger hashtext){
        //decifrar a mensagem e converter para bytes
        byte[] msg = decript_Message(ciphertext, sk, n).getBytes();
        //determinar o hash da mensagem decifrada
        byte[] h = SecurityUtil.hash(hash,msg);
        //decifrar o hash da mensagem cifrada 
        byte[] hash_msg = decript_Message(hashtext,sk,n).getBytes();
        //verificar se é igual ou não
        if(SecurityUtil.checkHash(h, hash_msg)){
            System.out.println("Is Equal");
        }else{
            System.out.println("Is NOT Equal");
        }

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
                        -l -length --length \033[3mlengthBit\033[0m, length of the prime, default 16
                        -v -verbose --verbose, shows verbose
                        =================================================================================
                        """
        );
    }
}
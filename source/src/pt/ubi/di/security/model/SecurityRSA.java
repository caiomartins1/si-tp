package pt.ubi.di.security.model;

import java.math.BigInteger;
import java.security.SecureRandom;

public class SecurityRSA {

    BigInteger N, p, q, M, d, e;

    //definir a pk do outro
    public SecurityRSA(BigInteger p, BigInteger N) {
        this.p = p;
        this.N = N;
    }
    
    public SecurityRSA(int bitLength, boolean verbose) {
        //SecureRandom r = new SecureRandom();
        //p = new BigInteger(bitLength, /*int certainty*/ ,r);
        p = SecurityUtil.generatePrime(bitLength,verbose);
        q = SecurityUtil.generatePrime(bitLength,verbose);
        generate_N(p,q);
    }

    public void generateValues(int bitLength, boolean verbose) {
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
    
    public void calculate_Keys(){
        // 1 < "e" < phi(n) ,
        // "e" e phi(n) sejam primos entre si.
        //começa em 3. Se começa em 1 o "d" seria encontrado imediatamente sendo o mesmo o valor de m
        e = new BigInteger("3");
        while(M.gcd(e).intValue() > 1){
            e = e.add(new BigInteger("2"));
        }
        //pk = (e,N)
        
        //e*d = 1 mod phi(n)
        // "d" seja inverso de "e"
        d = e.modInverse(M);
        //sk = d
    }

    //encriptação do hash da mensagem com a chave pública do cliente (other one)
    public BigInteger encript_Message(String plain_message, BigInteger pk, BigInteger n){
        byte[] convert = plain_message.getBytes();
        BigInteger encripted_msg = (new BigInteger(plain_message)).modPow(pk,n);
        //String encripted_msg = (new BigInteger(plain_message)).modPow(pk,n).toString();
        //devolve o BigInteger da mensagem encriptada com a chave publica
        return encripted_msg;
    }

    public BigInteger encript_hashMessage(String plain_message, BigInteger pk, BigInteger n){
        //byte[] convert = plain_message.getBytes();
        //determinar o hash da mensagem decifrada
        byte[] hmsg = SecurityUtil.hash(hash,plaintext);
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
    //private key
    public BigInteger getD() {
        return d;
    }
    // public key
    public BigInteger getE() {
        return e;
    }
    public void setE(BigInteger e){
        this.e = e;
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
    
}
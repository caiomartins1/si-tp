package pt.ubi.di.security.model;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SecurityRSA {

    BigInteger N, p, q, M, d, e, hash;
    private String hashtext = null;

    public SecurityRSA(BigInteger p, BigInteger q) {
        this.p = p;
        this.q = q;
    }
    
    public SecurityRSA(int bitLength, boolean verbose) {
        //SecureRandom r = new SecureRandom();
        //p = new BigInteger(bitLength, /*int certainty*/ ,r);
        p = SecurityUtil.generatePrime(bitLength,verbose);
        q = SecurityUtil.generatePrime(bitLength,verbose);
    }

    public void generateValues(int bitLength, boolean verbose) {
        p = SecurityUtil.generatePrime(bitLength,verbose);
        q = SecurityUtil.generatePrime(bitLength,verbose);
    }

    public void generate_N(BigInteger p, BigInteger q){
        //Calcula n = p * q
        N = p.multiply(q);
    }

    public void generate_phi_N(){
        //Calcula a função phi(n) = (p - 1)*(q - 1)
        M = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
    }
    
    public void calculate_Keys(BigInteger m){
        // 1 < "e" < phi(n) ,
        // "e" e phi(n) sejam primos entre si.
        //começa em 3. Se começa em 1 o "d" seria encontrado imediatamente sendo o mesmo o valor de m
        e = new BigInteger("3");
        while(m.gcd(e).intValue() > 1){ 
            e = e.add(new BigInteger("2"));
        }
        //pk = (e,N)
        
        //e*d = 1 mod phi(n)
        // "d" seja inverso de "e"
        d = e.modInverse(M);
        //sk = d
    }

    //-------------------------------------------------------
    //?integridade da mensagem enviada?
    //construção do hash da mensagem
    public BigInteger hash_Message(String input){
        try{
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte [] messageDigest = md.digest(input.getBytes());
            hash = new BigInteger(messageDigest);
            //hashtext = hash.toString();
            //return hashtext;
            return hash;
        }catch(NoSuchAlgorithmException e){
            System.out.println(e.getMessage());
        }
    }
    //-------------------------------------------------------
    //encriptação do hash da mensagem com a chave privada do utilizador
    public BigInteger encript_Message(BigInteger hash, BigInteger d, BigInteger N){
        BigInteger encripted_msg = hash.modPow(d,N);
        //String encripted_msg = hash.modPow(d,N).toString();
        return encripted_msg;
        //return encripted_msg;
    }

    //decifração do criptograma com a chave publica do utilizador 
    public BigInteger decript_Message(String hashtext, BigInteger e, BigInteger N){
        BigInteger decrpt_msg = new BigInteger(new BigInteger(hashtext).modPow(e,N).toByteArray());
        return decrpt_msg;
    }

    
    public BigInteger getP(){
        return p;
    }

    public BigInteger getQ(){
        return q;
    }

    public BigInteger getN(){
        return N;
    }

    public BigInteger getPhi(){
        return M;
    }
    
    public String getHashText(){
        return hashtext;
    }
}
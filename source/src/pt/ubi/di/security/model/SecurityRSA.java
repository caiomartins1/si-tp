package pt.ubi.di.security.model;

import java.math.BigInteger;
import java.security.SecureRandom;

public class SecurityRSA {

    BigInteger N, p, q, M, d, e;

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

    
}
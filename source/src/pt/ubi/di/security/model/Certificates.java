//package pt.ubi.di.security.model;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;

import javax.security.auth.Subject;

import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Certificates {
    //certificados - emitidos por user ou pelo agente confiança?
    //certificar que a chave pública pertence a x user
    BigInteger pk;
    BigInteger sk;
    //recebe a pk e sk
    final Date start = new Date();
    final Date until = Date.from(LocalDate.now().plusDays(365).atStartofDay().toInstance(ZoneOffset.UTC));
    final X509v3CertificateBuilder builder = new X509v3CertificateBuilder(new BigInteger(10, SecureRandom()),start,until,pk);
    
    ContentSigner signer = new JcaContentSigner("SHA512WithRSA").build(sk);
    Certificates certificate = new JcaX509CertificateConverter().setProvider(new BountyCastleProvider()).getCertificate(builder.build(signer));

    //return certificate;
}

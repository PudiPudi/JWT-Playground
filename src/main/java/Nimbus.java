import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import model.RSAPair;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Base64;

public class Nimbus {

    public static RSAPair generate() throws Exception{
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        RSAKey jwk = new RSAKey
                .Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey)keyPair.getPrivate())
                .keyUse(KeyUse.SIGNATURE)
                .keyID("LUDOVIC_JWT")
                .build();

        System.out.println("JWK");
        System.out.println("======================");
        System.out.println(jwk.toJSONObject());
        String n = String.valueOf(jwk.toJSONObject().get("n"));

//        System.out.println("======================\n\n");
//        System.out.println(Base64.getEncoder().encodeToString(n.getBytes()));
//        System.out.println(Base64URL.encode(n.getBytes()));
//        System.out.println(Base64.getUrlEncoder().encodeToString(n.getBytes()));
//        System.out.println(Base64.getEncoder().encodeToString(Base64.getUrlDecoder().decode(n.getBytes())));
//        System.out.println(n);
//
//        System.out.println("======================\n\n+");
//        System.out.println(Base64URL.encode(keyPair.getPublic().getEncoded()));
//        System.out.println(Base64URL.encode(keyPair.getPublic().getEncoded()));


//        System.out.println("======================\n\n");
//        // THIS WORKS -> BAD BASE64 ENCODING IN DEFAULT JWK
//        System.out.println(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
//        System.out.println("\n\n======================");


        System.out.println("Generate JWT\n");
        JWSSigner signer = new RSASSASigner(jwk);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("ludo")
                .issuer("http://ludovicmarchand.be")
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(jwk.getKeyID()).build(),
                claimsSet
        );

        signedJWT.sign(signer);
        String signedJWTString = signedJWT.serialize();

        System.out.println("Signed JWT");
        System.out.println("======================");
        System.out.println(signedJWTString);
        System.out.println("======================\n\n");

        return new RSAPair(jwk, signedJWTString);
    }

    public static void verify(RSAPair rsaPair) throws JOSEException, ParseException {

        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) rsaPair.jwk.toPublicKey());
        SignedJWT signedJWT = SignedJWT.parse(rsaPair.jws);

        System.out.println("\n\nNimbus Verify");
        System.out.println("======================");
        System.out.println(signedJWT.verify(verifier));
        System.out.println("======================\n\n");
    }
}

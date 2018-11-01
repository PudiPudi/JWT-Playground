import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import model.RSAPair;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

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
        System.out.println(jwk.toJSONObject().get("n"));
        System.out.println("======================");


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
}

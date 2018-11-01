import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import model.RSAPair;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class Auth0 {

    public static void generate() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();

        Algorithm algorithm = Algorithm.RSA256(rsaPublicKey, rsaPrivateKey);
        System.out.println(algorithm.getSigningKeyId() + "\n\n");
        String token = JWT.create()
                          .withIssuer("http://ludovicmarchand.be")
                          .withClaim("user", "Ludo")
                          .sign(algorithm);


        System.out.println("Signed JWT");
        System.out.println("======================");
        System.out.println(token);
        System.out.println("======================");
    }

    public static void verify(RSAPair rsaPair) throws Exception {
        KeyPair myKeyPair = rsaPair.jwk.toKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) myKeyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) myKeyPair.getPublic();

        Algorithm algorithm = Algorithm.RSA256(publicKey, privateKey);
        JWTVerifier verifier = JWT.require(algorithm).build();
        DecodedJWT jwt = verifier.verify(rsaPair.jws);

        System.out.println("Signed JWT");
        System.out.println("======================");
        System.out.println(verifier.verify(rsaPair.jws));
        System.out.println(jwt.getPayload());
        System.out.println("======================");
    }
}

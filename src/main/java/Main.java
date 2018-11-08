import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import model.RSAPair;

import java.util.Optional;

public class Main {

    public static void main(String[] args) throws Exception {
        System.out.println("Hello World");

//        Auth0.generate();
        RSAPair rsaPair = Nimbus.generate();

        // TODO: verify using auth0
//        Auth0.verify(rsaPair);
        // JJWT.verify(rsaPair);


        JWK jwk = rsaPair.jwk;
        JWKSet set = new JWKSet(jwk);
        String jwkString = set.toJSONObject(false).toString();
        System.out.println(jwkString);

        // Set from string
        JWKSet newSet = JWKSet.parse(jwkString);
        Optional<JWK> newKeyOptional = newSet.getKeys().stream().findFirst();

        if (!newKeyOptional.isPresent()) {
            throw new Exception("No JWKs present");
        }

        JWK newJWK = newKeyOptional.get();
        if (newJWK.getKeyType().equals(KeyType.RSA)) {
            RSAKey rsaKey = RSAKey.parse(jwk.toJSONObject());

            System.out.println(rsaKey.toPublicKey().toString());
        }
    }
}

import java.security.*;
import java.security.interfaces.*;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import model.RSAPair;

public class Main {

    public static void main(String[] args) throws Exception {
        System.out.println("Hello World");

//        Auth0.generate();
        RSAPair rsaPair = Nimbus.generate();

        // TODO: verify using auth0
//        Auth0.verify(rsaPair);
        JJWT.verify(rsaPair);
    }
}

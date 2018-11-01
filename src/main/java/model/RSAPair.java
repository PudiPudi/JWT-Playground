package model;

import com.nimbusds.jose.jwk.RSAKey;

public class RSAPair {
    public RSAKey jwk;
    public String jws;

    public RSAPair(RSAKey jwk, String signedJWTString) {
        this.jwk = jwk;
        this.jws = signedJWTString;
    }
}

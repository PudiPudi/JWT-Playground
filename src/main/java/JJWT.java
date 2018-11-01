import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import model.RSAPair;

import java.security.Key;

public class JJWT {
    public static void verify(RSAPair rsaPair) throws Exception {

        Key publicKey = rsaPair.jwk.toPublicKey();

        Jws<Claims> jws = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(rsaPair.jws);
        System.out.println("Verifier JJWT");
        System.out.println("======================");
        System.out.println(jws.getBody());
        System.out.println("======================");
    }
}

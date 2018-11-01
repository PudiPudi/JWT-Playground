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

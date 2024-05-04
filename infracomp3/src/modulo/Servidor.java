package modulo;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.Random;

public class Servidor {


    PublicKey llavepublica;
    Signature firma;
    PrivateKey llaveprivada;
    byte[] sb;
    

    BigInteger p = new BigInteger("db0acb9c43a5ae273fe0931e62ba95c2b9f66fa9ad929f4ac0b43950a9e5e4b60620bda4a578b51517d7e6c7b47b1d16813c99a1bcdbc1a083bc913c87576aaf3b2f4d9b54cf9c26ea95111abb656384912bdb639b90cf994162d6407f4f1561d66f79aea5decbad665c4e4e3ca7809ab0a397f0bcc589275b449a9c86366d07", 16);
  

    BigInteger g = new BigInteger("2");
    SecureRandom rand = new SecureRandom();
    

    BigInteger x = new BigInteger("0");
    


    public  Servidor() throws NoSuchAlgorithmException{

        //creacion de llaves

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2045);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // creacion de x
        BigInteger maxLimit = new BigInteger("500000");
        BigInteger minLimit = new BigInteger("100000");
        BigInteger bigInteger = maxLimit.subtract(minLimit);
        Random randNum = new Random();
        int len = maxLimit.bitLength();
        BigInteger res = new BigInteger(len, randNum);
        if (res.compareTo(minLimit) < 0)
           res = res.add(minLimit);
        if (res.compareTo(bigInteger) >= 0)
           res = res.mod(bigInteger).add(minLimit);
           System.out.println("x = "+res);
     
        this.x = res;
        this.llavepublica  = publicKey;
        this.llaveprivada = privateKey;

    }

    public  byte[] firmar(String texto)  throws NoSuchAlgorithmException, InvalidKeyException, SignatureException{
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(llaveprivada);
        signature.update(texto.getBytes());
        byte[] signatureBytes = signature.sign();
        
       
        
        return signatureBytes;

    }

    public PublicKey getLlavepublica() {
        return llavepublica;
    }


    public byte[] getSb() {
        return sb;
    }

    public Signature getFirma() {
        return firma;
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getG() {
        return g;
    }

    public BigInteger getGX() {

        BigInteger result = BigInteger.ONE;
        while (x.signum() > 0) {
                 if (x.testBit(0)) result = result.multiply(g);
                 g = g.multiply(g);
                 x = x.shiftRight(1);
         }

        return result;
        
    }

    public String keytostring(PublicKey llave){
        byte[] byte_pubkey = llave.getEncoded();
        String str_key = Base64.getEncoder().encodeToString(byte_pubkey);
        
        return str_key;
    }
   
   



}
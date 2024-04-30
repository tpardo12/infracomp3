package modulo;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.Cipher;

public class Cliente {


    public void verificarfirma (  Signature firma, PublicKey publicKey, byte[] signatureBytes, String reto) throws SignatureException, InvalidKeyException{
        firma.initVerify(publicKey);
        firma.update(reto.getBytes());
        boolean isVerified = firma.verify(signatureBytes);
        System.out.println("Verificacion de la firma: " + isVerified);
    }
    public String generarReto ()
    {

        SecureRandom rand = new SecureRandom();
        int rand_int1 = rand.nextInt(2000000000);
        String str1 = Integer.toString(rand_int1); 
        return str1;
    }


    

}

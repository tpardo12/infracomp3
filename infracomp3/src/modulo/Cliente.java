package modulo;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.Cipher;

public class Cliente {


    public void verificarfirma (  Signature firma, PublicKey publicKey, byte[] signatureBytes, String reto) throws SignatureException, InvalidKeyException{
        firma.initVerify(publicKey);
        firma.update(reto.getBytes());
        boolean isVerified = firma.verify(signatureBytes);
        System.out.println("Signature verification status: " + isVerified);
    }


    

}

package modulo;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public class Servidor {


    PublicKey llavepublica;
    Signature firma;
    PrivateKey llaveprivada;
    byte[] sb;


    public  Servidor() throws NoSuchAlgorithmException{

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        this.llavepublica  = publicKey;
        this.llaveprivada = privateKey;

        System.out.println("Firma utilizando llave privada " );

    }

    public void firmar(String texto)  throws NoSuchAlgorithmException, InvalidKeyException, SignatureException{
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(llaveprivada);
        signature.update(texto.getBytes());
        byte[] signatureBytes = signature.sign();
        this.firma = signature;
        this.sb = signatureBytes;
        System.out.println("Firma utilizando llave privada " + new String(signatureBytes));

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
   
   



}
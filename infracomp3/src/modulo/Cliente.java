package modulo;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

public class Cliente {


    public Boolean verificarfirma (   PublicKey publicKey, byte[] signatureBytes, String reto) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException{
        
        Signature verificador = Signature.getInstance("SHA256withRSA");
        verificador.initVerify(publicKey);
        verificador.update(reto.getBytes());
        boolean isVerified = verificador.verify(signatureBytes);
        System.out.println("Verificacion de la firma: " + isVerified);

        return isVerified;
    }
    
    public String generarReto ()
    {

        SecureRandom rand = new SecureRandom();
        int rand_int1 = rand.nextInt(2000000000);
        String str1 = Integer.toString(rand_int1); 
        return str1;
    }

    public PublicKey stringtobyte (String str_key) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException{
        
        byte[] byte_pubkey = Base64.getDecoder().decode(str_key);
        KeyFactory factory = KeyFactory.getInstance("SHA256withRSA");
        PublicKey public_key = (ECPublicKey) factory.generatePublic(new X509EncodedKeySpec(byte_pubkey));
        return public_key;
    }


    

}

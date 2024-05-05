package modulo;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
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
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Cliente {

    
    BigInteger g = new BigInteger("2");
    BigInteger  y  = new BigInteger("0");
    private String kab;
    private String kmac;


    public Cliente(){

        BigInteger maxLimit = new BigInteger("5000");
        BigInteger minLimit = new BigInteger("1000");
        BigInteger bigInteger = maxLimit.subtract(minLimit);
        Random randNum = new Random();
        int len = maxLimit.bitLength();
        BigInteger res = new BigInteger(len, randNum);
        if (res.compareTo(minLimit) < 0)
           res = res.add(minLimit);
        if (res.compareTo(bigInteger) >= 0)
           res = res.mod(bigInteger).add(minLimit);

        this.y = res;


    }

    public void digest ( String x){
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            byte[] messageDigest = md.digest(x.getBytes());
            BigInteger no = new BigInteger(1, messageDigest);
            String hashtext = no.toString(16);
            while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }
            String kab = hashtext.substring(0, 32);
            String kmac = hashtext.substring(32, 64);
            this.kab = kab;
            this.kmac = kmac;
            System.out.println(hashtext);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    public BigInteger generarGY (){

        

        BigInteger result = BigInteger.ONE;
           while (y.signum() > 0) {
                    if (y.testBit(0)) result = result.multiply(g);
                    g = g.multiply(g);
                    y = y.shiftRight(1);
            }
   
        return result;
    }


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

    public BigInteger powN(BigInteger x, BigInteger y){

        BigInteger result = BigInteger.ONE;
        while (y.signum() > 0) {
                 if (y.testBit(0)) result = result.multiply(x);
                 x = x.multiply(x);
                 y = y.shiftRight(1);
         }
        

        return result;
    }

    public static final String ALGORITHM = "HmacSHA256";

    public static String calculateHMac(String key, String data) throws Exception {
        Mac sha256_HMAC = Mac.getInstance(ALGORITHM);

        SecretKeySpec secret_key = new SecretKeySpec(key.getBytes("UTF-8"), ALGORITHM);
        sha256_HMAC.init(secret_key);

        return byteArrayToHex(sha256_HMAC.doFinal(data.getBytes("UTF-8")));
    }

    public static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for(byte b: a)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public BigInteger getG() {
        return g;
    }

    public BigInteger getY() {
        return y;
    }

    public String getKab() {
        return kab;
    }

    public String getKmac() {
        return kmac;
    }


    

}

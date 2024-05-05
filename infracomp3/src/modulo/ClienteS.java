package modulo;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;



public class ClienteS {

    public static void main(String[] args) throws Exception {
        

        final String host  ="127.0.0.1";
        final int puerto = 5000;
        DataInputStream in; 
        DataOutputStream out; 
        ObjectInputStream intO;
        ObjectOutputStream outO;

        
        try {

            Socket sc  = new Socket(host, puerto);
            in = new DataInputStream(sc.getInputStream());
            out =new DataOutputStream(sc.getOutputStream());
            intO = new ObjectInputStream(sc.getInputStream());
            outO = new ObjectOutputStream(sc.getOutputStream());

            Cliente cliente = new Cliente();
            String reto = cliente.generarReto();

            out.writeUTF(reto);

            byte[] firmaReto =  (byte[])  intO.readObject();       
            System.out.println(firmaReto);                    
            PublicKey llavepublica = (PublicKey)  intO.readObject();      
            boolean vfirmaReto = cliente.verificarfirma(llavepublica,firmaReto, reto); 
            out.writeBoolean(vfirmaReto);
            BigInteger p = (BigInteger) intO.readObject(); 
            BigInteger g = (BigInteger) intO.readObject();
            BigInteger gx = (BigInteger) intO.readObject();
            BigInteger y = cliente.getY();
            byte[] iv = (byte[]) intO.readObject();
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            // firma de valores
            byte[] firmaValores =  (byte[])  intO.readObject();   
            String valores = p.toString() + g.toString() + gx.toString();
            boolean vfirmaValores = cliente.verificarfirma(llavepublica,firmaValores, valores); 
            out.writeBoolean(vfirmaValores);
            BigInteger gy = cliente.generarGY();
            // enviar gy
            outO.writeObject(gy);
            BigInteger kmaster = (gx.modPow(y, p));
            cliente.digest(kmaster.toString());
            String kab = cliente.getKab();
            String kmac = cliente.getKmac();

            System.out.println("kab  " + kab);
            System.out.println("kmac " +  kmac);

            Boolean  continuar = in.readBoolean(); 

            while (continuar == false ) {
                   
                 System.out.println("esperando respuesta del servidor ........");
            }

            String login = "loginusuario1"; // Ejemplo de login
            String contrasenia = "contrasenia12343";  // Ejemplo contraseña 
            

            Cipher cipherl = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec kabKey = new SecretKeySpec(kab.getBytes(), "AES");
            cipherl.init(Cipher.ENCRYPT_MODE, kabKey, ivSpec);
            byte[] loginCifrado = cipherl.doFinal(login.getBytes());
 
            outO.writeObject(loginCifrado);

            Cipher cipherc = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipherc.init(Cipher.ENCRYPT_MODE, kabKey, ivSpec);
            byte[] contraseniacifrado = cipherc.doFinal(contrasenia.getBytes());
            outO.writeObject(contraseniacifrado);


            // espacio para la  respuesta del servidor 

            String consulta = "consulta";

            Cipher ciphercon = Cipher.getInstance("AES/CBC/PKCS5Padding");
            ciphercon.init(Cipher.ENCRYPT_MODE, kabKey, ivSpec);
            byte[] consultaCifrado = ciphercon.doFinal(consulta.getBytes());
            outO.writeObject(consultaCifrado);

            String hmac = Cliente.calculateHMac(kmac, consulta);
           

            outO.writeObject(hmac);

           
            byte[] respuestaCifrada = (byte[]) intO.readObject();
            String hmacRespuesta = (String) intO.readObject();
            
            Cipher cipherR = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipherR.init(Cipher.DECRYPT_MODE, kabKey, ivSpec);
            byte[] respuestades = cipherR.doFinal(respuestaCifrada);
            String respuesta = new String(respuestades);

            System.out.println("respuesta del hmac " + hmacRespuesta);
            System.out.println("respuesta  " + respuesta);
      
        } catch (IOException es) {
            // TODO: handle exception
        }

    }


}

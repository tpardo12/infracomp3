package modulo;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ClienteS {

public static void main(String args[]) throws IOException, SignatureException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, Exception{


    InetAddress address=InetAddress.getLocalHost();
    final int puerto = 4445;
    DataInputStream in; 
    DataOutputStream out; 
    ObjectInputStream intO;
    ObjectOutputStream outO;
    Socket sc; 



    System.out.println("Client Address : "+address);
    System.out.println("Enter Data to echo Server ( Enter QUIT to end):");
    sc  = new Socket(address, puerto);
    in = new DataInputStream(sc.getInputStream());
    out =new DataOutputStream(sc.getOutputStream());
    intO = new ObjectInputStream(sc.getInputStream());
    outO = new ObjectOutputStream(sc.getOutputStream());
  
    Cliente cliente = new Cliente();
        String reto = cliente.generarReto();

        out.writeUTF(reto);                                               // 1  envia reto

        byte[] firmaReto =  (byte[])  intO.readObject();                //  3 recibe  firma 
        PublicKey llavepublica = (PublicKey)  intO.readObject();        // 3.1 recibe llave publica del servidor 

        boolean vfirmaReto = cliente.verificarfirma(llavepublica,firmaReto, reto);  // 4 verifica la firma 
        out.writeBoolean(vfirmaReto);


        BigInteger p = (BigInteger) intO.readObject();              //  7 recibe p,g,gx, iv
        BigInteger g = (BigInteger) intO.readObject();
        BigInteger gx = (BigInteger) intO.readObject();
        BigInteger y = cliente.getY();                             // 7 calcula 
        byte[] iv = (byte[]) intO.readObject();                    
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        byte[] firmaValores =  (byte[])  intO.readObject();     // 7 recibe firma de valores
        String valores = p.toString() + g.toString() + gx.toString(); // 8 concatena los valores
        boolean vfirmaValores = cliente.verificarfirma(llavepublica,firmaValores, valores); 
        out.writeBoolean(vfirmaValores);                  // 8 verifica los valores
        BigInteger gy = cliente.generarGY();             //10 genera gy
        // enviar gy
        outO.writeObject(gy);                          // 10 envia gy
        BigInteger kmaster = (gx.modPow(y, p));       // 11a calcula la llave master
        cliente.digest(kmaster.toString());          //  11a calcula el digest
        String kab = cliente.getKab();                 // 11a Obtiene la llave simetrica para cifrado 
        String kmac = cliente.getKmac();                // 11a Obtiene la llave simetrica para Hmac

        

        Boolean  continuar = in.readBoolean(); 

        while (continuar == false ) {               // 12.  espera respuesta de continuar
               
             System.out.println("esperando respuesta del servidor ........");
        }

        String login = "logusuario"; // Ejemplo de login
        String contrasenia = "contraseniausuario";  // Ejemplo contraseña 

        Cipher cipherl = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec kabKey = new SecretKeySpec(kab.getBytes(), "AES");
        cipherl.init(Cipher.ENCRYPT_MODE, kabKey, ivSpec);
        byte[] loginCifrado = cipherl.doFinal(login.getBytes());  // 13. envia login cifrado 
 
        outO.writeObject(loginCifrado);

        Cipher cipherc = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherc.init(Cipher.ENCRYPT_MODE, kabKey, ivSpec);
        byte[] contraseniacifrado = cipherc.doFinal(contrasenia.getBytes());
        outO.writeObject(contraseniacifrado);                      // 13 envia cotraseña cifrada




        Boolean validacionlog = in.readBoolean();               // 16. recibe el OK o el error 
        if (validacionlog == false) {
            System.out.println("usuario o contraseña incorrecta");
        }
        else {
            System.out.println("logeado correctamente");
        }

        String consulta = "consulta";                
       
     

        Cipher ciphercon = Cipher.getInstance("AES/CBC/PKCS5Padding");
        ciphercon.init(Cipher.ENCRYPT_MODE, kabKey, ivSpec);
        byte[] consultaCifrado = ciphercon.doFinal(consulta.getBytes());
        outO.writeObject(consultaCifrado);  
                                                        // 17 envia  consulta cifrada 
        long startTime = System.currentTimeMillis();

        String hmac = Cliente.calculateHMac(kmac, consulta);
        long endTime = System.currentTimeMillis() - startTime; 
        System.out.println("tiempo en generar mac  : " + endTime);

        outO.writeObject(hmac);                      // 18 envia  el Hmac de la consulta  

       
        byte[] respuestaCifrada = (byte[]) intO.readObject();   // 19.1  entra la respuesta cifrada 
        String hmacRespuesta = (String) intO.readObject();      // 20.1  entra el hmac
        
        Cipher cipherR = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherR.init(Cipher.DECRYPT_MODE, kabKey, ivSpec);
        byte[] respuestades = cipherR.doFinal(respuestaCifrada);
        String respuesta = new String(respuestades);           // 21 descifra la respuesta 
        

        String verificarHmac = Cliente.calculateHMac(kmac, respuesta) ; // 21 verifica hmac
            
            
        if (hmacRespuesta.equals(verificarHmac) ) {      
            System.out.println("Hmac de respuesta verificado correctamente");
            
        }
        else{
            System.out.println("Hmac de respuesta no  verificado correctamente");
            sc.close();
        }

        System.out.println("la respuesta del servidor es : " + respuesta);
    

}
}
package modulo;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ServidorS {

    /**
     * @param args
     * @throws Exception 
     */
    public static void main(String[] args) throws Exception  {
        
        ServerSocket servidor = null;
        Socket sc = null; 
        final int puerto = 5000;
        DataInputStream in; 
        DataOutputStream out; 
        ObjectOutputStream outO;
        ObjectInputStream intO;

        try {

            servidor = new ServerSocket(puerto);
            Servidor serv = new Servidor();
         

            while (true) {

                sc = servidor.accept();
                in = new DataInputStream(sc.getInputStream());
                out =new DataOutputStream(sc.getOutputStream());
                outO = new ObjectOutputStream(sc.getOutputStream());
                intO = new ObjectInputStream(sc.getInputStream());
    
                String mensaje = in.readUTF();                                      // reto del cliente
                byte[] firmaReto = serv.firmar(mensaje);   
                System.out.println(firmaReto);                             // firma el reto 
                PublicKey llavepublica = serv.getLlavepublica();                   
                outO.writeObject(firmaReto);                                        // envia firma
                outO.writeObject(llavepublica);                                // envia k+
                boolean vfirmaReto = in.readBoolean();
                if (vfirmaReto == false) {
                    sc.close();
                }
                BigInteger p = serv.getP();
                BigInteger g = serv.getG();
                BigInteger x = serv.getX();
                BigInteger gx = serv.getGX();
               
                outO.writeObject(p);
                outO.writeObject(g); 
                outO.writeObject(gx);
                byte[] vector = serv.generarV();
                IvParameterSpec  iv = new IvParameterSpec(vector);
                outO.writeObject(vector);
                byte[] firmaValores = serv.firmar( p.toString() + g.toString() + gx.toString()); 
                outO.writeObject(firmaValores);
                boolean vfirmaValores = in.readBoolean();
                if (vfirmaValores == false){
                    sc.close();
                }
                BigInteger gy = (BigInteger) intO.readObject();
                
                BigInteger kmaster = (gy.modPow(x, p));
                serv.digest(kmaster.toString());
                String kab = serv.getKab();
                String kmac = serv.getKmac();

                Boolean continuar = true;

                out.writeBoolean(continuar);
               
                

                byte[] loginCifrado = (byte[]) intO.readObject();
                byte[] contraseniaCifrado = (byte[]) intO.readObject();
                byte[] consultaCifrada = (byte[]) intO.readObject();
                String hmacConsulta = (String) intO.readObject();


               
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                SecretKeySpec kabKey = new SecretKeySpec(kab.getBytes(), "AES");
                cipher.init(Cipher.DECRYPT_MODE, kabKey, iv);
                byte[] loginDescifrado = cipher.doFinal(loginCifrado);
                String login = new String(loginDescifrado);

                Cipher cipherc = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipherc.init(Cipher.DECRYPT_MODE, kabKey, iv);
                byte[] contraseniaDescifrado = cipherc.doFinal(contraseniaCifrado);
                String contrasenia = new String(contraseniaDescifrado);

                Cipher ciphercon = Cipher.getInstance("AES/CBC/PKCS5Padding");
                ciphercon.init(Cipher.DECRYPT_MODE, kabKey, iv);
                byte[] consultaDescifrado = ciphercon.doFinal(consultaCifrada);
                String consulta = new String(consultaDescifrado);

                

                System.out.println(login);
                System.out.println(contrasenia);
                System.out.println(consulta);
                

                String respuesta = "respuesta a " + consulta;

                Cipher cipherR = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipherR.init(Cipher.ENCRYPT_MODE, kabKey, iv);
                byte[] respuestaCifrada = cipherR.doFinal(respuesta.getBytes());
                outO.writeObject(respuestaCifrada);

                String hmac = Servidor.calculateHMac(kmac, respuesta);
                System.out.println(hmac);
                outO.writeObject(hmac);

                

            }
            
        } catch (IOException ex) {
            // TODO: handle exception
        }

       
    }

   
}




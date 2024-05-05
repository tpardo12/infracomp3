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
    

                String mensaje = in.readUTF();                                      // paso 1 reto del cliente
                byte[] firmaReto = serv.firmar(mensaje);   
                // System.out.println(firmaReto);                             // paso 2  firma el reto 
                PublicKey llavepublica = serv.getLlavepublica();                   
                outO.writeObject(firmaReto);                                        //  paso 3 envia firma
                outO.writeObject(llavepublica);                                // paso 3.1 envia k+
                boolean vfirmaReto = in.readBoolean();                        //  paso 5 Recibe la confirmacion
                if (vfirmaReto == false) {                                   //  paso 5.1 valida la confirmacion
                    sc.close();
                }
                BigInteger p = serv.getP();                                // 7.1 obtiene  P 
                BigInteger g = serv.getG();                               //  7.2 obtiene g
                BigInteger x = serv.getX();                              //   7.3 pbtiene x 
                BigInteger gx = serv.getGX();                           //    7.4  obtiene Gx 
               
                outO.writeObject(p);                                  //    7.5 envia p
                outO.writeObject(g);                                 //     7.6 envia g
                outO.writeObject(gx);                               //      7.7 envia gx
                byte[] vector = serv.generarV();
                IvParameterSpec  iv = new IvParameterSpec(vector); //       7.8 envia vector
                outO.writeObject(vector);
                byte[] firmaValores = serv.firmar( p.toString() + g.toString() + gx.toString());  // 7.9 firma valores concatenados
                outO.writeObject(firmaValores);
                boolean vfirmaValores = in.readBoolean();
                if (vfirmaValores == false){              // 9 valida la verificacion
                    sc.close();
                }
                BigInteger gy = (BigInteger) intO.readObject(); // 10 Recibe Gy
                
                BigInteger kmaster = (gy.modPow(x, p));  // 11b calcula la llave master
                serv.digest(kmaster.toString());         // 11b calcula el digest
                String kab = serv.getKab();              // 11b k simetrica
                String kmac = serv.getKmac();            // 11b k para hmac

                Boolean continuar = true;                // envia confirmacion para continuar

                out.writeBoolean(continuar);
               
                

                byte[] loginCifrado = (byte[]) intO.readObject();        //13 entra login cifrado 
                byte[] contraseniaCifrado = (byte[]) intO.readObject();  // 13 entra contraseña cifrada
                


               
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                SecretKeySpec kabKey = new SecretKeySpec(kab.getBytes(), "AES");
                cipher.init(Cipher.DECRYPT_MODE, kabKey, iv);
                byte[] loginDescifrado = cipher.doFinal(loginCifrado);
                String login = new String(loginDescifrado);                // 15.1 descifra log in 

                Cipher cipherc = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipherc.init(Cipher.DECRYPT_MODE, kabKey, iv);
                byte[] contraseniaDescifrado = cipherc.doFinal(contraseniaCifrado);
                String contrasenia = new String(contraseniaDescifrado);   // 15.2 descifra contrseña 

                
                

                System.out.println("log in del ususario : " + login); 
                System.out.println("COntrseña del susuario " + contrasenia);

                if (login.equals("logusuario")  && contrasenia.equals("contraseniausuario")) {  // hace validaciones de log in y contraseña 
                    out.writeBoolean(true);
                }
                else{
                    out.writeBoolean(false);
                }

                byte[] consultaCifrada = (byte[]) intO.readObject();      // 17.1 recibe consulta cifrada 
                String hmacConsulta = (String) intO.readObject();        // 18 recibe hmac

                Cipher ciphercon = Cipher.getInstance("AES/CBC/PKCS5Padding");
                ciphercon.init(Cipher.DECRYPT_MODE, kabKey, iv);
                byte[] consultaDescifrado = ciphercon.doFinal(consultaCifrada);
                String consulta = new String(consultaDescifrado);    // 17.2 descifra consulta  

                
                String verificarHmac = Servidor.calculateHMac(kmac, consulta) ; // 18.1 verifica hmac
                
                
                if (hmacConsulta.equals(verificarHmac) ) {      
                    System.out.println("Hmac de consulta verificado correctamente");
                    
                }
                else{
                    sc.close();
                }
                System.out.println("la consulta del usuario fue : " + consulta);


                String respuesta = "respuesta a " + consulta;

                Cipher cipherR = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipherR.init(Cipher.ENCRYPT_MODE, kabKey, iv);
                byte[] respuestaCifrada = cipherR.doFinal(respuesta.getBytes());
                outO.writeObject(respuestaCifrada);  // 19 cifra respuesta y la envia 

                String hmac = Servidor.calculateHMac(kmac, respuesta);
                //System.out.println(hmac);
                outO.writeObject(hmac);            // envia hmac de la respuesta

                

            }
            
        } catch (IOException ex) {
            // TODO: handle exception
        }

       
    }

   
}




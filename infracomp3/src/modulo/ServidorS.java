package modulo;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;

public class ServidorS {

    /**
     * @param args
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException  {
        
        ServerSocket servidor = null;
        Socket sc = null; 
        final int puerto = 5000;
        DataInputStream in; 
        DataOutputStream out; 
        ObjectOutputStream outO;

        try {

            servidor = new ServerSocket(puerto);
            Servidor serv = new Servidor();
         

            while (true) {

                sc = servidor.accept();
                in = new DataInputStream(sc.getInputStream());
                out =new DataOutputStream(sc.getOutputStream());
                outO = new ObjectOutputStream(sc.getOutputStream());
    
                String mensaje = in.readUTF();                                      // reto del cliente
                byte[] firmaReto = serv.firmar(mensaje);   
                System.out.println(firmaReto);                             // firma el reto 
                PublicKey llavepublica = serv.getLlavepublica();                   
                outO.writeObject(firmaReto);                                        // envia firma
                outO.writeObject(llavepublica);                                // envia k+
                boolean vfirma = in.readBoolean();
                if (vfirma == false) {
                    sc.close();
                }
                outO.writeObject(serv.getP());
                outO.writeObject(serv.getG()); 
                BigInteger gx = serv.getGX();
                outO.writeObject(gx);
                byte[] firmaValores = serv.firmar(serv.getP().toString()  ); 
                
                outO.writeObject(firmaValores);
            }
            
        } catch (IOException ex) {
            // TODO: handle exception
        }

       
    }

}

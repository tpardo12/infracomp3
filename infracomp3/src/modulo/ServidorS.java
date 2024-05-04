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
     * @throws ClassNotFoundException 
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, ClassNotFoundException  {
        
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

                System.out.println("kab  " + kab);
                System.out.println("kmac " +  kmac);
            


            }
            
        } catch (IOException ex) {
            // TODO: handle exception
        }

       
    }

}

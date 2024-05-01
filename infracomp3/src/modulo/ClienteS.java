package modulo;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;



public class ClienteS {

    public static void main(String[] args) throws ClassNotFoundException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        

        final String host  ="127.0.0.1";
        final int puerto = 5000;
        DataInputStream in; 
        DataOutputStream out; 
        ObjectInputStream intO;

        
        try {

            Socket sc  = new Socket(host, puerto);
            in = new DataInputStream(sc.getInputStream());
            out =new DataOutputStream(sc.getOutputStream());
            intO = new ObjectInputStream(sc.getInputStream());

            Cliente cliente = new Cliente();
            String reto = cliente.generarReto();

            out.writeUTF(reto);

            byte[] firma =  (byte[])  intO.readObject();                           
            PublicKey llavepublica = (PublicKey)  intO.readObject();      
 
            cliente.verificarfirma(llavepublica,firma, reto); 
      
        } catch (IOException es) {
            // TODO: handle exception
        }

    }


}

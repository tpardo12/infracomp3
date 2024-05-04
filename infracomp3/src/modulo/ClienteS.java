package modulo;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
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
            byte[] firmaValores =  (byte[])  intO.readObject();   
            String valores = p.toString() + g.toString() + gx.toString();
            boolean vfirmaValores = cliente.verificarfirma(llavepublica,firmaValores, valores); 
            out.writeBoolean(vfirmaValores);
            BigInteger gy = cliente.generarGY();
           
            outO.writeObject(gy);
            BigInteger kmaster = (gx.modPow(y, p));
            cliente.digest(kmaster.toString());
            String kab = cliente.getKab();
            String kmac = cliente.getKmac();

            System.out.println("kab  " + kab);
            System.out.println("kmac " +  kmac);

            
            


      
        } catch (IOException es) {
            // TODO: handle exception
        }

    }


}

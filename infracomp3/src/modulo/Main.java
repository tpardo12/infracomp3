package modulo;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

public class Main {

    

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        
        Servidor servidor = new Servidor();
        Cliente cliente = new Cliente();
        servidor.firmar("pepe"); 

        cliente.verificarfirma(servidor.getFirma(), servidor.getLlavepublica(), servidor.getSb(), "pepe");
       
    }

   

  
      
}

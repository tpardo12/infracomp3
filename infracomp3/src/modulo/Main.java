package modulo;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

public class Main {

    

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        
        Servidor servidor = new Servidor();
        Cliente cliente = new Cliente();
        String reto = cliente.generarReto();
        servidor.firmar(reto); 
        System.out.println(reto);
        cliente.verificarfirma( servidor.getLlavepublica(), servidor.getSb(), reto);
       
        
    }

   

  
      
}

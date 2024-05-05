package modulo;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Ejecutador {
    
    public static void main(String[] args) throws SignatureException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException, Exception {
        
        Integer clientes = 16;
        for (int i = 0; i < clientes; i++) {
            ClienteS nc = new ClienteS();
            ClienteS.main(args);
        }
    }
}

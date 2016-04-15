import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.InputStream;
import java.io.*;
import java.net.ServerSocket;
import java.util.Arrays;
import java.net.Socket;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.*;
import java.security.cert.*;

public class SecureServer {

    public final static int SOCKET_PORT = 4321;

    public static X509Certificate getCert(String filename) throws Exception {
        X509Certificate cert = null;
        File f = new File(filename);
        FileInputStream fis = new FileInputStream(f);
        cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(fis);
        return cert;
    }

    public static void main (String [] args ) throws Exception {
        FileInputStream fis = null;
        BufferedInputStream bis = null;
        OutputStream os = null;
        ServerSocket servsock = null;
        Socket sock = null;
        String clientMsg = null;

        Key rsaPrivateKey = PrivateKeyReader.get("privateServer.der");
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, rsaPrivateKey);
        try {
            servsock = new ServerSocket(SOCKET_PORT);
            //while (true) {
            System.out.println("Waiting...");
            try {
                sock = servsock.accept();
                System.out.println("Accepted connection : " + sock);
                byte [] mybytearray  = new byte[1000];
                InputStream is = sock.getInputStream();
                os = sock.getOutputStream();

                // server listen for "proof"
                int bytesRead = is.read(mybytearray,0,mybytearray.length);
                clientMsg = new String(mybytearray);
                System.out.println("bytes read: " + bytesRead);

                // server send signed message ("server")
                if (clientMsg.contains("proof")) {
                    System.out.println("client requesting for proof");
                    System.out.println("sending client rsa key");
                    String message = new String("server");
                    byte[] signedMessage = rsaCipher.doFinal(message.getBytes());
                    os.write(signedMessage);
                    os.flush();
                }

                // server listen for "cert"
                Arrays.fill(mybytearray, (byte) 0);
                bytesRead = is.read(mybytearray,0,mybytearray.length);
                clientMsg = new String(mybytearray);
                System.out.println("bytes read: " + bytesRead);

                // server send X509Certifate
                if (clientMsg.contains("cert")) {
                    System.out.println("client requesting for cert");
                    System.out.println("sending client cert");
                    X509Certificate serverCert = getCert("secStore.crt");
                    ObjectOutputStream ooStream = new ObjectOutputStream(os);
                    ooStream.writeObject(serverCert);
                }

                // server listen for nonce
                byte[] encryptedNonce = new byte[128];
                bytesRead = is.read(encryptedNonce,0,encryptedNonce.length);
                System.out.println("bytes read: " + bytesRead);
                System.out.println("received encrpyted nonce");

                // decrypt nonce and sign it
                System.out.println("replying with signed nonce");
                rsaCipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
                byte[] decryptedNonce = rsaCipher.doFinal(encryptedNonce);

                rsaCipher.init(Cipher.ENCRYPT_MODE, rsaPrivateKey);
                os.write(rsaCipher.doFinal(decryptedNonce));
                os.flush();
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                if (bis != null) bis.close();
                if (sock!=null) sock.close();
            }
        } finally {
            if (servsock != null) servsock.close();
        }
    }
}

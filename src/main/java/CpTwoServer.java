import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.lang.reflect.Array;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * Created by User on 14/4/2016.
 */
public class CpTwoServer {

    public final static int SOCKET_PORT = 4321;  // you may change this

    public final static String serverMsg = new String("server");
    public final static String uploadedMsg = new String("uploaded");

    public static void main (String [] args ) throws Exception {


        Key rsaPrivateKey = null;
        X509Certificate cert = null;

        SecureInputStream socketInStream = null;
        SecureOutputStream socketOutStream = null;
        ObjectOutputStream objectOutStream = null;
        BufferedOutputStream fileOutStream = null;
        Socket sock = null;
        String clientMsg = null;
        ServerSocket servsock = null;

        // encrypt
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        try {
            rsaPrivateKey = PrivateKeyReader.get("privateServer.der");
            cert = getCert("secStore.crt");
            servsock = new ServerSocket(SOCKET_PORT);
            while (true) {
                System.out.println("Waiting...");
                try {
                    sock = servsock.accept();
                    socketOutStream = new SecureOutputStream(sock.getOutputStream());
                    socketInStream = new SecureInputStream(sock.getInputStream());
                    socketOutStream.setupRSA(rsaPrivateKey);
                    socketInStream.setupRSA(rsaPrivateKey);

                    // server listen for "proof"
                    clientMsg = socketInStream.readUTF();

                    if (!clientMsg.equals("proof")) {
                        System.err.println("expected: \"proof\"");
                        throw new RuntimeException();
                    }

                    // server send signed message ("server")
                    System.out.println("client requesting for proof");
                    System.out.println("sending client rsa key");
                    socketOutStream.secureWriteUTF(serverMsg);
                    socketOutStream.flush();

                    // server listen for "cert"
                    clientMsg = socketInStream.readUTF();

                    // server send X509Certifate
                    if (!clientMsg.equals("cert")) {
                        System.err.println("expected: \"cert\"");
                        throw new RuntimeException();
                    }
                    System.out.println("client requesting for cert");
                    System.out.println("sending client cert");
                    socketOutStream.writeCert(cert);

                    // server listen for nonce
                    String nonce = socketInStream.secureReadUTF();
                    System.out.println("received nonce: " + nonce);
                    socketOutStream.secureWriteUTF(nonce);
                    socketOutStream.flush();


        //**********************************part 1 done******************************************************

                    // obtain the AES key from client
                    SecretKey key = (SecretKey) socketInStream.secureReadObject();
                    Cipher ecipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                    ecipher.init(Cipher.DECRYPT_MODE,key);

                    //read the file name
                    String fileName = socketInStream.secureReadUTF();
                    System.out.println("filename to be transferred over: " + fileName);

                    //read the file length to determine the file size
                    int fileSize = (int)socketInStream.secureReadLong();
                    System.out.println("file size is "+fileSize);
                    byte[] encryptedFile = new byte[fileSize];

                    //decrypt encrypted file
                    int totalBytesRead = 0;
                    int bytesRead = 0;
                    while (totalBytesRead < fileSize) {
                        bytesRead = socketInStream.read(encryptedFile, totalBytesRead, fileSize-totalBytesRead);
                        if (bytesRead < 0) {
                            if (totalBytesRead < fileSize) {
                                System.err.println("size not same");
                            }
                        }
                        totalBytesRead += bytesRead;
                    }
                    System.out.println("decrypting file");
                    byte[] decryptedFile = ecipher.doFinal(encryptedFile);

                    // write file
                    File file = new File("upload", fileName);
                    fileOutStream = new BufferedOutputStream(new FileOutputStream(file));
                    fileOutStream.write(decryptedFile);
                    fileOutStream.flush();

                    // notify client that it is done
                    System.out.println("file uploaded, notifying client");
                    socketOutStream.secureWriteUTF(uploadedMsg);
                    socketOutStream.flush();

                } catch (Exception e) {
                    e.printStackTrace();}
                finally {
                    if (socketInStream != null) socketInStream.close();
                    if (socketOutStream != null) socketOutStream.close();
                    if (fileOutStream != null) fileOutStream.close();
                    if (sock!=null) sock.close();
                }
            }
        }
        finally {
            if (servsock != null) servsock.close();
        }
    }
    public static X509Certificate getCert(String filename) throws Exception {
        X509Certificate cert = null;
        File f = new File(filename);
        FileInputStream fis = new FileInputStream(f);
        cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(fis);
        return cert;
    }
}

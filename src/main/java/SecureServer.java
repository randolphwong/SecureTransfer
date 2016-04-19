import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
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
    public final static String serverMsg = new String("server");
    public final static String uploadedMsg = new String("uploaded");

    public static X509Certificate getCert(String filename) throws Exception {
        X509Certificate cert = null;
        File f = new File(filename);
        FileInputStream fis = new FileInputStream(f);
        cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(fis);
        return cert;
    }

    public static void main (String [] args ) throws Exception {
        SecureInputStream socketInStream = null;
        SecureOutputStream socketOutStream = null;
        ObjectOutputStream objectOutStream = null;
        BufferedOutputStream fileOutStream = null;
        ServerSocket servsock = null;
        Socket sock = null;
        String clientMsg = null;
        byte[] clientByte  = new byte[128];

        Key rsaPrivateKey = PrivateKeyReader.get("privateServer.der");
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        try {
            servsock = new ServerSocket(SOCKET_PORT);
            while (true) {
                System.out.println("Waiting...");
                try {
                    sock = servsock.accept();
                    System.out.println("Accepted connection : " + sock);
                    socketOutStream = new SecureOutputStream(sock.getOutputStream());
                    socketInStream = new SecureInputStream(sock.getInputStream());
                    socketOutStream.setupRSA(rsaPrivateKey);
                    socketInStream.setupRSA(rsaPrivateKey);

                    // server listen for "proof"
                    clientMsg = socketInStream.readUTF();

                    if (!clientMsg.equals("proof")) {
                        System.err.println("expected: \"proof\"");
                        System.exit(-1);
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
                        System.exit(-1);
                    }
                    System.out.println("client requesting for cert");
                    System.out.println("sending client cert");
                    X509Certificate serverCert = getCert("secStore.crt");
                    socketOutStream.writeCert(serverCert);

                    // server listen for nonce
                    String nonce = socketInStream.secureReadUTF();
                    System.out.println("received nonce: ");
                    socketOutStream.secureWriteUTF(nonce);
                    socketOutStream.flush();

                    // server listen for file upload
                    clientMsg = socketInStream.secureReadUTF();
                    if (!clientMsg.equals("file")) {
                        System.err.println("expected: \"file\"");
                        System.exit(-1);
                    }

                    // server listen for filename
                    System.out.println("client preparing to send file.");
                    String filename = socketInStream.secureReadUTF();
                    System.out.println("filename received: " + filename);

                    // server listen for filesize
                    Long fileSize = socketInStream.secureReadLong();
                    System.out.println(fileSize + " to be transferred over.");

                    // open file to write
                    fileOutStream = new BufferedOutputStream(new FileOutputStream(new File("upload", filename)));

                    // prepare for decryption
                    byte[] decryptedFilePart;
                    while (fileSize > 0) {
                        decryptedFilePart = socketInStream.secureRead();
                        if (fileSize < 117) {
                            fileOutStream.write(decryptedFilePart, 0, fileSize.intValue());
                        } else {
                            fileOutStream.write(decryptedFilePart, 0, decryptedFilePart.length);
                        }
                        fileSize -= decryptedFilePart.length;
                        if (fileSize < 0) {
                            break;
                        }
                    }
                    fileOutStream.flush();

                    // server notify client that file has been uploaded
                    System.out.println("file uploaded, notifying client");
                    socketOutStream.secureWriteUTF(uploadedMsg);
                    socketOutStream.flush();

                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    if (socketInStream != null) socketInStream.close();
                    if (socketOutStream != null) socketOutStream.close();
                    if (fileOutStream != null) fileOutStream.close();
                    if (sock!=null) sock.close();
                }
            }
        } finally {
            if (servsock != null) servsock.close();
        }
    }
}

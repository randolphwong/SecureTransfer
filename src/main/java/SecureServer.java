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
        DataInputStream socketInStream = null;
        DataOutputStream socketOutStream = null;
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
                    socketOutStream = new DataOutputStream(new BufferedOutputStream(sock.getOutputStream()));
                    socketInStream = new DataInputStream(new BufferedInputStream(sock.getInputStream()));
                    objectOutStream = new ObjectOutputStream(sock.getOutputStream());

                    // server listen for "proof"
                    clientMsg = socketInStream.readUTF();

                    if (!clientMsg.equals("proof")) {
                        System.err.println("expected: \"proof\"");
                        System.exit(-1);
                    }

                    // server send signed message ("server")
                    System.out.println("client requesting for proof");
                    System.out.println("sending client rsa key");
                    rsaCipher.init(Cipher.ENCRYPT_MODE, rsaPrivateKey);
                    byte[] signedMessage = rsaCipher.doFinal(serverMsg.getBytes());
                    socketOutStream.write(signedMessage, 0, signedMessage.length);
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
                    objectOutStream.writeObject(serverCert);

                    // server listen for nonce
                    byte[] encryptedNonce = new byte[128];
                    int bytesRead = socketInStream.read(encryptedNonce,0,encryptedNonce.length);
                    System.out.println("received encrpyted nonce: " + bytesRead + " bytes read.");

                    // decrypt nonce and sign it
                    System.out.println("replying with signed nonce");
                    rsaCipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
                    byte[] decryptedNonce = rsaCipher.doFinal(encryptedNonce);

                    rsaCipher.init(Cipher.ENCRYPT_MODE, rsaPrivateKey);
                    byte[] signedNonce = rsaCipher.doFinal(decryptedNonce);
                    socketOutStream.write(signedNonce, 0, signedNonce.length);
                    socketOutStream.flush();

                    // server listen for file upload
                    socketInStream.read(clientByte, 0, clientByte.length);
                    rsaCipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
                    clientMsg = new String(rsaCipher.doFinal(clientByte));
                    if (!clientMsg.equals("file")) {
                        System.err.println("expected: \"file\"");
                        System.exit(-1);
                    }

                    // server listen for filename
                    System.out.println("client preparing to send file.");
                    socketInStream.read(clientByte, 0, clientByte.length);
                    String filename = new String(rsaCipher.doFinal(clientByte));
                    System.out.println("filename received: " + filename);

                    // server listen for filesize
                    socketInStream.read(clientByte, 0, clientByte.length);
                    Long fileSize = (Long) Serializer.deserialize(rsaCipher.doFinal(clientByte));
                    System.out.println(fileSize + " to be transferred over.");

                    // open file to write
                    fileOutStream = new BufferedOutputStream(new FileOutputStream(new File("upload", filename)));

                    // prepare for decryption
                    rsaCipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
                    byte[] encryptedFilePart = new byte[128];

                    while ((bytesRead = socketInStream.read(encryptedFilePart, 0, encryptedFilePart.length)) > 0) {
                        byte[] decryptedFilePart = rsaCipher.doFinal(encryptedFilePart);
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
                    socketOutStream.writeUTF(uploadedMsg);
                    socketOutStream.flush();

                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    if (socketInStream != null) socketInStream.close();
                    if (socketOutStream != null) socketOutStream.close();
                    if (objectOutStream != null) objectOutStream.close();
                    if (fileOutStream != null) fileOutStream.close();
                    if (sock!=null) sock.close();
                }
            }
        } finally {
            if (servsock != null) servsock.close();
        }
    }
}

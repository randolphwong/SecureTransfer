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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.*;
import java.security.cert.*;

public class SecureServer {

    public final static int SOCKET_PORT = 4321;
    public static Key rsaPrivateKey;
    public static X509Certificate cert;

    public static X509Certificate getCert(String filename) throws Exception {
        X509Certificate cert = null;
        File f = new File(filename);
        FileInputStream fis = new FileInputStream(f);
        cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(fis);
        return cert;
    }

    public static void main (String [] args ) throws Exception {
        ExecutorService exec = Executors.newCachedThreadPool();
        ServerSocket servsock = null;
        int i = 0;
        try {
            rsaPrivateKey = PrivateKeyReader.get("privateServer.der");
            cert = getCert("secStore.crt");
            servsock = new ServerSocket(SOCKET_PORT);

            while (true) {
                Socket sock = servsock.accept();
                exec.submit(new ClientHandler(sock, ++i));
                //new Thread(new ClientHandler(sock, ++i)).start();
            }
        } finally {
            if (servsock != null) servsock.close();
        }
    }
}

class ClientHandler implements Runnable {

    public final static String serverMsg = new String("server");
    public final static String uploadedMsg = new String("uploaded");

    private SecureInputStream socketInStream;
    private SecureOutputStream socketOutStream;
    private ObjectOutputStream objectOutStream;
    private BufferedOutputStream fileOutStream;
    private Socket sock;
    private String clientMsg;
    private byte[] clientByte;
    private int id;

    public ClientHandler(Socket sock, int id) {
        this.sock = sock;
        this.id = id;
        clientByte = new byte[128];
    }

    public void run() {
        try {
            socketOutStream = new SecureOutputStream(sock.getOutputStream());
            socketInStream = new SecureInputStream(sock.getInputStream());
            socketOutStream.setupRSA(SecureServer.rsaPrivateKey);
            socketInStream.setupRSA(SecureServer.rsaPrivateKey);

            System.out.println("handling client " + id);

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
            socketOutStream.writeCert(SecureServer.cert);

            // server listen for nonce
            String nonce = socketInStream.secureReadUTF();
            System.out.println("received nonce: " + nonce);
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

            System.out.println("client " + id + " session complete");
            System.out.println();
        } catch (Exception e) {
            System.err.println("client " + id + " upload failed.");
            e.printStackTrace();
        } finally {
            try {
                if (socketInStream != null) socketInStream.close();
                if (socketOutStream != null) socketOutStream.close();
                if (fileOutStream != null) fileOutStream.close();
                if (sock!=null) sock.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}

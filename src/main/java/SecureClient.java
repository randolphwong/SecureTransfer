import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.*;
import java.net.Socket;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.*;
import java.security.cert.*;

import java.util.Random;

public class SecureClient {

    public final static int SOCKET_PORT = 4321;
    public final static String SERVER = "localhost";
    public final static String proofMsg = new String("proof");
    public final static String certMsg = new String("cert");
    public final static String fileMsg = new String("file");

    public static X509Certificate getCert(String filename) throws Exception {
        X509Certificate cert = null;
        File f = new File(filename);
        FileInputStream fis = new FileInputStream(f);
        cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(fis);
        return cert;
    }

    public static boolean verifyCert(X509Certificate cert) throws Exception {
        X509Certificate CA_cert = getCert("CA.crt");
        try {
            cert.verify(CA_cert.getPublicKey());
            cert.checkValidity();
            return cert.getSubjectX500Principal().toString().contains("randolph_wong@mymail.sutd.edu.sg");
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static void main (String [] args ) throws IOException {

        if (args.length < 1) {
            System.out.println("Usage: java Client filename");
            System.exit(-1);
        }

        int bytesRead;
        DataOutputStream socketOutStream = null;
        DataInputStream socketInStream = null;
        ObjectInputStream objectInStream = null;
        BufferedInputStream fileInStream = null;
        Socket sock = null;
        PublicKey serverKey = null;
        Random random = new Random();
        byte[] serverProof = new byte[128];
        byte[] serialisedMsg = null;

        try {
            sock = new Socket(SERVER, SOCKET_PORT);
            System.out.println("Connected");
            socketOutStream = new DataOutputStream(new BufferedOutputStream(sock.getOutputStream()));
            socketInStream = new DataInputStream(new BufferedInputStream(sock.getInputStream()));

            // client ask for proof
            System.out.println("sending to server: \"" + proofMsg + "\"");
            socketOutStream.writeUTF(proofMsg);
            socketOutStream.flush();

            // client receive proof message
            bytesRead = socketInStream.read(serverProof,0,serverProof.length);
            System.out.println("received proof: " + bytesRead + " bytes read.");

            // client ask for cert
            System.out.println("sending to server: \"" + certMsg + "\"");
            socketOutStream.writeUTF(certMsg);
            socketOutStream.flush();

            // client receive cert
            objectInStream = new ObjectInputStream(sock.getInputStream());
            X509Certificate cert = (X509Certificate) objectInStream.readObject();
            System.out.println("received certificate");

            // verify certificate
            System.out.println("verifying certificate");
            if (verifyCert(cert)) {
                System.out.println("verification succesfull");
            } else {
                System.out.println("verification failed");
                System.exit(-1);
            }

            // extract public key
            serverKey = cert.getPublicKey();

            // verify server's initial message
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, serverKey);
            String unecryptedServerProof = new String(rsaCipher.doFinal(serverProof));
            if (!unecryptedServerProof.equals("server")) {
                System.out.println("server proof verification failed");
                System.exit(-1);
            }

            // encrypt nonce
            rsaCipher.init(Cipher.ENCRYPT_MODE, serverKey);
            String nonceMsg = Long.toString(random.nextLong());
            byte[] encryptedNonce = rsaCipher.doFinal(nonceMsg.getBytes());

            // send encrypted nonce
            System.out.println("sending to encrypted nonce: " + nonceMsg);
            socketOutStream.write(encryptedNonce, 0, encryptedNonce.length);
            socketOutStream.flush();

            // client listen for signed nonce
            byte[] signedNonce = new byte[128];
            bytesRead = socketInStream.read(signedNonce,0,signedNonce.length);
            System.out.println("received signed nonce");

            // un-sign nonce and verify
            System.out.println("verifying nonce");
            rsaCipher.init(Cipher.DECRYPT_MODE, serverKey);
            String unsignedNonce = new String(rsaCipher.doFinal(signedNonce));
            System.out.println("unsignedNonce: " + unsignedNonce);
            if (unsignedNonce.equals(nonceMsg)) {
                System.out.println("nonce verification sucessful");
            } else {
                System.out.println("verification failed");
                System.exit(-1);
            }

            // open file to transfer and determine how to split it for transmission
            File file = new File(args[0]);
            fileInStream = new BufferedInputStream(new FileInputStream(file));
 
            // client notify server that it will start sending files
            System.out.println("sending to server: \"" + fileMsg + "\"");
            socketOutStream.writeUTF(fileMsg);
            socketOutStream.flush();

            // client notify server of name of file
            socketOutStream.writeUTF(file.getName());
            socketOutStream.flush();

            // send server file size
            long fileSize = file.length();
            System.out.println("sending to server: \"" + fileSize + "\"");
            socketOutStream.writeLong(fileSize);
            socketOutStream.flush();

            // split files up, encrypt and send to server
            byte[] filePart = new byte[117];
            byte[] encryptedFilePart;
            rsaCipher.init(Cipher.ENCRYPT_MODE, serverKey);

            long startTime, endTime;
            startTime = System.currentTimeMillis();

            while ((bytesRead = fileInStream.read(filePart, 0, filePart.length)) > 0) {
                encryptedFilePart = rsaCipher.doFinal(filePart);
                socketOutStream.write(encryptedFilePart, 0, encryptedFilePart.length);
                socketOutStream.flush();
            }

            // client listen for successful upload notification
            System.out.println("waiting for server's acknowledgement");
            String serverMsg = socketInStream.readUTF();
            if (!serverMsg.equals("uploaded")) {
                System.err.println("file upload failed.");
                System.exit(-1);
            }

            System.out.println("file successfully uploaded.");
            endTime = System.currentTimeMillis();
            System.out.println("upload time: " + (endTime - startTime) + " ms");

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (socketInStream != null) socketInStream.close();
            if (socketOutStream != null) socketOutStream.close();
            if (objectInStream != null) objectInStream.close();
            if (fileInStream != null) fileInStream.close();
            if (sock != null) sock.close();
        }
    }
}


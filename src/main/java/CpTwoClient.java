/**
 * Created by User on 14/4/2016.
 */
import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.*;
import java.net.Socket;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.security.*;
import java.security.spec.*;
import java.security.cert.*;

import java.util.Arrays;
import java.util.Random;

public class CpTwoClient {

    public final static int SOCKET_PORT = 4321;      // you may change this
    public final static String SERVER_HOSTNAME = "localhost";  // localhost
    public final static String proofMsg = new String("proof");
    public final static String certMsg = new String("cert");

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
            return false;
        }
    }

    public static void main (String [] args ) throws IOException {

        if (args.length < 1) {
            System.out.println("Usage: java Client filename");
            System.exit(-1);
        }

        int bytesRead;
        SecureOutputStream socketOutStream = null;
        SecureInputStream socketInStream = null;
        BufferedInputStream fileInStream = null;
        Socket sock = null;
        PublicKey serverKey = null;
        Random random = new Random();
        byte[] serverProof = new byte[128];

        try {
            sock = new Socket(SERVER_HOSTNAME, SOCKET_PORT);
            System.out.println("Connected");
            socketOutStream = new SecureOutputStream(sock.getOutputStream());
            System.out.println("hi");

            // client ask for proof
            System.out.println("sending to server: \"" + proofMsg + "\"");
            socketOutStream.writeUTF(proofMsg);
            socketOutStream.flush();

            socketInStream = new SecureInputStream(sock.getInputStream());
            // client receive proof message
            bytesRead = socketInStream.read(serverProof,0,serverProof.length);
            System.out.println("received proof: " + bytesRead + " bytes read.");

            // client ask for cert
            System.out.println("sending to server: \"" + certMsg + "\"");
            socketOutStream.writeUTF(certMsg);
            socketOutStream.flush();

            // client receive cert
            X509Certificate cert = socketInStream.readCert();
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
            socketOutStream.setupRSA(serverKey);
            socketInStream.setupRSA(serverKey);


            // verify server's initial message
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, serverKey);
            String unecryptedServerProof = new String(rsaCipher.doFinal(serverProof));
            if (!unecryptedServerProof.equals("server")) {
                System.out.println("server proof verification failed");
                System.exit(-1);
            }

            // send encrypted nonce
            String nonceMsg = Long.toString(random.nextLong());
            System.out.println("sending encrypted nonce: " + nonceMsg);
            socketOutStream.secureWriteUTF(nonceMsg);
            socketOutStream.flush();

            // client listen for signed nonce
            String receivedNonce = socketInStream.secureReadUTF();
            System.out.println("received nonce: " + receivedNonce);

            // verify nonce
            if (receivedNonce.equals(nonceMsg)) {
                System.out.println("nonce verification sucessful");
            } else {
                System.out.println("verification failed");
                System.exit(-1);
            }
//****************************part 1 done******************************************************

            // generate AES and send to server
            SecretKey key = KeyGenerator.getInstance("AES").generateKey();
            socketOutStream.secureWriteObject(key);

            // open file to send
            File file = new File(args[0]);
            byte[] bFile = new byte[(int) file.length()];
            FileInputStream fileInputStream = new FileInputStream(file);
            fileInputStream.read(bFile);
            fileInputStream.close();

            // encrypt file with AES
            Cipher ecipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            ecipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encFile = ecipher.doFinal(bFile);

            // send server the file name
            String fileName = file.getName();
            System.out.println("sending server file name: " + fileName);
            socketOutStream.secureWriteUTF(fileName);

            // send server the file size
            System.out.println("sending server encrypted file length: "+encFile.length);
            socketOutStream.secureWriteLong((long)encFile.length);
            socketOutStream.flush();

            // send encrypted file
            long startTime, endTime;
            startTime = System.currentTimeMillis();
            System.out.println("sending encrypted file to server");
            socketOutStream.write(encFile,0,encFile.length);
            socketOutStream.flush();

            // client listen for successful upload notification
            System.out.println("waiting for server's acknowledgement");
            String serverMsg = socketInStream.secureReadUTF();
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
            if (fileInStream != null) fileInStream.close();
            if (sock != null) sock.close();
        }
    }

}

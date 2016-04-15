import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
        int current = 0;
        OutputStream os = null;
        InputStream is;
        FileOutputStream fos = null;
        BufferedOutputStream bos = null;
        Socket sock = null;
        PublicKey serverKey = null;
        Random random = new Random();
        byte[] serverProof = new byte[128];
        String nonceMsg = new String("Nonce");
        FileInputStream fis = null;
        BufferedInputStream bis = null;

        try {
            sock = new Socket(SERVER, SOCKET_PORT);
            System.out.println("Connected");
            os = sock.getOutputStream();
            is = sock.getInputStream();

            // client ask for proof
            System.out.println("sending to server: \"" + proofMsg + "\"");
            os.write(proofMsg.getBytes());
            os.flush();

            // client receive proof message
            is = sock.getInputStream();
            bytesRead = is.read(serverProof,0,serverProof.length);
            System.out.println("received proof: " + bytesRead + " bytes read.");

            // client ask for cert
            System.out.println("sending to server: \"" + certMsg + "\"");
            os.write(certMsg.getBytes());
            os.flush();

            // client receive cert
            ObjectInputStream ois = new ObjectInputStream(is);
            X509Certificate cert = (X509Certificate) ois.readObject();
            System.out.println("received certificate");

            // verify certificate
            System.out.println("verifying certificate");
            boolean verified = verifyCert(cert);
            if (verified) {
                System.out.println("verification succesfull");
            } else {
                System.out.println("verification failed");
                System.exit(-1);
            }

            // extract public key
            serverKey = cert.getPublicKey();

            // encrypt nonce
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, serverKey);
            nonceMsg = String.format("%s%d", nonceMsg, random.nextLong());
            byte[] encryptedNonce = rsaCipher.doFinal(nonceMsg.getBytes());

            // send encrypted nonce
            System.out.println("sending to encrypted nonce: " + nonceMsg);
            os.write(encryptedNonce);
            os.flush();

            // client listen for signed nonce
            byte[] signedNonce = new byte[128];
            bytesRead = is.read(signedNonce,0,signedNonce.length);
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
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (fos != null) fos.close();
            if (bos != null) bos.close();
            if (sock != null) sock.close();
        }
    }
}


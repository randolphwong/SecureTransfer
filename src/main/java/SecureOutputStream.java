import java.io.DataOutputStream;
import java.io.BufferedOutputStream;
import java.io.OutputStream;
import java.io.ObjectOutputStream;
import java.io.IOException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;

public class SecureOutputStream {

    private DataOutputStream outStream;
    private ObjectOutputStream objectOutStream;
    private Cipher rsaCipher;
    private byte[] msgToSend;

    public SecureOutputStream(OutputStream outStream) throws IOException {
        this.outStream = new DataOutputStream(new BufferedOutputStream(outStream));
        this.objectOutStream = new ObjectOutputStream(outStream);
        this.msgToSend = new byte[128];
    }

    public void setupRSA(Key rsaKey) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException {
        rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, rsaKey);
    }

    public void writeUTF(String msg) throws IOException {
        outStream.writeUTF(msg);
    }

    public void writeCert(X509Certificate cert) throws IOException, ClassNotFoundException {
        objectOutStream.writeObject(cert);
    }

    public void secureWriteUTF(String msg) throws IOException, IllegalBlockSizeException, BadPaddingException {
        msgToSend = rsaCipher.doFinal(msg.getBytes());
        outStream.write(msgToSend, 0, msgToSend.length);
    }

    public void secureWriteLong(Long msg) throws IOException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException {
        msgToSend = rsaCipher.doFinal(Serializer.serialize(msg));
        outStream.write(msgToSend, 0, msgToSend.length);
    }

    public void secureWrite(byte[] b) throws IOException, IllegalBlockSizeException, BadPaddingException {
        msgToSend = rsaCipher.doFinal(b);
        outStream.write(msgToSend, 0, msgToSend.length);
    }

    public void flush() throws IOException {
        outStream.flush();
    }

    public void close() throws IOException {
        outStream.close();
        objectOutStream.close();
    }
}

import java.io.DataInputStream;
import java.io.BufferedInputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.IOException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;

public class SecureInputStream {

    private DataInputStream inStream;
    private ObjectInputStream objectInStream;
    private Cipher rsaCipher;
    private byte[] receivedMsg;

    public SecureInputStream(InputStream inStream) throws IOException {
        this.inStream = new DataInputStream(new BufferedInputStream(inStream));
        this.objectInStream = new ObjectInputStream(inStream);
        this.receivedMsg = new byte[128];
    }

    public void setupRSA(Key rsaKey) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException {
        rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, rsaKey);
    }

    public int read(byte[] b, int off, int len) throws IOException {
        return inStream.read(b, off, len);
    }

    public String readUTF() throws IOException {
        return inStream.readUTF();
    }

    public X509Certificate readCert() throws IOException, ClassNotFoundException {
        return (X509Certificate) objectInStream.readObject();
    }

    public String secureReadUTF() throws IOException, IllegalBlockSizeException, BadPaddingException {
        inStream.read(receivedMsg, 0, receivedMsg.length);
        return new String(rsaCipher.doFinal(receivedMsg));
    }

    public long secureReadLong() throws IOException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException {
        inStream.read(receivedMsg, 0, receivedMsg.length);
        return (Long) Serializer.deserialize(rsaCipher.doFinal(receivedMsg));
    }

    public Object secureReadObject() throws IOException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException {
        int objSize = (int)secureReadLong();
        
        byte[] decryptedObj = new byte[objSize];
        byte[] received;
        for (int i = 0; i < objSize; ) {
            received = secureRead();
            System.arraycopy(received, 0, decryptedObj, i, received.length);
            i += received.length;
        }
        return Serializer.deserialize(decryptedObj);
    }

    public byte[] secureRead() throws IOException, IllegalBlockSizeException, BadPaddingException {
        inStream.read(receivedMsg, 0, receivedMsg.length);
        return rsaCipher.doFinal(receivedMsg);
    }

    public void close() throws IOException {
        inStream.close();
        objectInStream.close();
    }
}

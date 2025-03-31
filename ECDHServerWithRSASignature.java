/* import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.KeyAgreement;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ECDHServerWithRSASignature {

    // For demonstration, generate the server's RSA key pair.
    // In production, load your persistent keys.
    private static KeyPair serverRSAKeyPair;
    // Assume the client's RSA public key is already trusted and exchanged.
    private static PublicKey clientRSAPublicKey;

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Generate or load RSA keys.
        serverRSAKeyPair = generateRSAKeyPair();
        clientRSAPublicKey = loadClientRSAPublicKey(); // Stub: implement proper key retrieval

        // Generate an ephemeral ECDH key pair using the named curve "prime256v1".
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");
        keyPairGenerator.initialize(ecSpec);
        KeyPair ecdhKeyPair = keyPairGenerator.generateKeyPair();
        // Get the encoded form of the ECDH public key.
        byte[] ecdhPubKeyEncoded = ecdhKeyPair.getPublic().getEncoded();

        // Sign the ECDH public key using the server's RSA private key.
        byte[] signature = signData(ecdhPubKeyEncoded, serverRSAKeyPair.getPrivate());

        // Set up a server socket.
        ServerSocket serverSocket = new ServerSocket(9000);
        System.out.println("ECDH Server started, waiting for client connection...");
        Socket socket = serverSocket.accept();
        System.out.println("Client connected.");

        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());

        // Send the ECDH public key and its RSA signature.
        oos.writeObject(ecdhPubKeyEncoded);
        oos.writeObject(signature);
        oos.flush();
        System.out.println("Sent ECDH public key and RSA signature.");

        // Receive the client's ECDH public key and RSA signature.
        byte[] clientEcdhPubKeyEncoded = (byte[]) ois.readObject();
        byte[] clientSignature = (byte[]) ois.readObject();
        System.out.println("Received client's ECDH public key and RSA signature.");

        // Verify the client's signature using the client's RSA public key.
        if (!verifySignature(clientEcdhPubKeyEncoded, clientSignature, clientRSAPublicKey)) {
            throw new SecurityException("Client's RSA signature verification failed!");
        }
        System.out.println("Client's RSA signature verified.");

        // Reconstruct the client's ECDH public key.
        KeyFactory keyFactory = KeyFactory.getInstance("ECDH", "BC");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(clientEcdhPubKeyEncoded);
        PublicKey clientEcdhPubKey = keyFactory.generatePublic(keySpec);

        // Perform the ECDH key agreement.
        KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH", "BC");
        keyAgree.init(ecdhKeyPair.getPrivate());
        keyAgree.doPhase(clientEcdhPubKey, true);
        byte[] sharedSecret = keyAgree.generateSecret();
        System.out.println("Server computed shared secret: " + Arrays.toString(sharedSecret));

        ois.close();
        oos.close();
        socket.close();
        serverSocket.close();
    }

    private static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static PublicKey loadClientRSAPublicKey() throws Exception {
        // In production, load the client's RSA public key from a trusted source.
        // Here, we simulate it by generating a key pair (this RSA public key will differ from the client's real one).
        KeyPair clientKeyPair = generateRSAKeyPair();
        return clientKeyPair.getPublic();
    }

    private static byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(data);
        return signer.sign();
    }

    private static boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(data);
        return verifier.verify(signature);
    }
}
 */

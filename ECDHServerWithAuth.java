import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ECDHServerWithAuth {
	// Pre-shared symmetric key for authentication (in a real system, keep this
	// secret and secure)
	// TODO trocar por chave publica do client
	private static final byte[] PSK = "SuperSecretKey123".getBytes();

	public static void main(String[] args) throws Exception {
		// 1. Add Bouncy Castle as a security provider.
		Security.addProvider(new BouncyCastleProvider());

		// 2. Define the EC parameters using the named curve "prime256v1".
		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");

		// 3. Generate the server's ECDH key pair.
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");
		keyPairGenerator.initialize(ecSpec);
		KeyPair serverKeyPair = keyPairGenerator.generateKeyPair();

		// 4. Compute HMAC for the server's public key.
		byte[] serverPubKeyEncoded = serverKeyPair.getPublic().getEncoded();
		Mac mac = Mac.getInstance("HmacSHA256");
		SecretKeySpec keySpec = new SecretKeySpec(PSK, "HmacSHA256");
		mac.init(keySpec);
		byte[] serverMac = mac.doFinal(serverPubKeyEncoded);

		// 5. Set up a server socket.
		ServerSocket serverSocket = new ServerSocket(9000);
		System.out.println("ECDH Server started, waiting for client connection...");
		Socket socket = serverSocket.accept();
		System.out.println("Client connected.");

		// 6. Create object streams for communication.
		ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
		ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());

		// 7. Send server's public key and its HMAC to the client.
		oos.writeObject(serverPubKeyEncoded);
		oos.writeObject(serverMac);
		oos.flush();
		System.out.println("Server public key and MAC sent.");

		// 8. Receive client's public key and HMAC.
		byte[] clientPubKeyEncoded = (byte[]) ois.readObject();
		byte[] clientMacReceived = (byte[]) ois.readObject();
		System.out.println("Received client's public key and MAC.");

		// 9. Verify client's HMAC.
		mac.reset();
		mac.init(new SecretKeySpec(PSK, "HmacSHA256"));
		byte[] computedClientMac = mac.doFinal(clientPubKeyEncoded);
		if (!Arrays.equals(clientMacReceived, computedClientMac)) {
			throw new SecurityException("Client public key MAC verification failed!");
		}
		System.out.println("Client MAC verified.");

		// 10. Reconstruct client's public key.
		KeyFactory keyFactory = KeyFactory.getInstance("ECDH", "BC");
		X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(clientPubKeyEncoded);
		PublicKey clientPubKey = keyFactory.generatePublic(keySpecX509);

		// 11. Perform the key agreement.
		KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH", "BC");
		keyAgree.init(serverKeyPair.getPrivate());
		keyAgree.doPhase(clientPubKey, true);
		byte[] sharedSecret = keyAgree.generateSecret();

		System.out.println("Server computed shared secret: " + Arrays.toString(sharedSecret));

		// 12. Clean up.
		ois.close();
		oos.close();
		socket.close();
		serverSocket.close();
	}
}

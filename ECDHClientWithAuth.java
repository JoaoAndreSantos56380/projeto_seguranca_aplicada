import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyAgreement;
import java.security.Security;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ECDHClientWithAuth {
	// Pre-shared symmetric key for authentication (must be identical to the
	// server's PSK)
	private static final byte[] PSK = "SuperSecretKey123".getBytes();

	public static void main(String[] args) throws Exception {
		// 1. Add Bouncy Castle as a security provider.
		Security.addProvider(new BouncyCastleProvider());

		// 2. Connect to the ECDH server.
		Socket socket = new Socket("localhost", 9000);
		System.out.println("Connected to ECDH server.");

		// 3. Create object streams for communication.
		ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
		ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());

		// 4. Receive the server's public key and its HMAC.
		byte[] serverPubKeyEncoded = (byte[]) ois.readObject();
		byte[] serverMacReceived = (byte[]) ois.readObject();
		System.out.println("Received server public key and MAC.");

		// 5. Verify server's HMAC.
		Mac mac = Mac.getInstance("HmacSHA256");
		SecretKeySpec keySpec = new SecretKeySpec(PSK, "HmacSHA256");
		mac.init(keySpec);
		byte[] computedServerMac = mac.doFinal(serverPubKeyEncoded);
		if (!Arrays.equals(serverMacReceived, computedServerMac)) {
			throw new SecurityException("Server public key MAC verification failed!");
		}
		System.out.println("Server MAC verified.");

		// 6. Reconstruct server's public key.
		KeyFactory keyFactory = KeyFactory.getInstance("ECDH", "BC");
		X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(serverPubKeyEncoded);
		PublicKey serverPubKey = keyFactory.generatePublic(keySpecX509);

		// 7. Define the EC parameters (using the same named curve "prime256v1").
		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");

		// 8. Generate the client's ECDH key pair.
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");
		keyPairGenerator.initialize(ecSpec);
		KeyPair clientKeyPair = keyPairGenerator.generateKeyPair();

		// 9. Compute HMAC for the client's public key.
		byte[] clientPubKeyEncoded = clientKeyPair.getPublic().getEncoded();
		mac.reset();
		mac.init(new SecretKeySpec(PSK, "HmacSHA256"));
		byte[] clientMac = mac.doFinal(clientPubKeyEncoded);

		// 10. Send the client's public key and its HMAC to the server.
		oos.writeObject(clientPubKeyEncoded);
		oos.writeObject(clientMac);
		oos.flush();
		System.out.println("Client public key and MAC sent.");

		// 11. Perform the key agreement.
		KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH", "BC");
		keyAgree.init(clientKeyPair.getPrivate());
		keyAgree.doPhase(serverPubKey, true);
		byte[] sharedSecret = keyAgree.generateSecret();

		System.out.println("Client computed shared secret: " + Arrays.toString(sharedSecret));

		// 12. Clean up.
		ois.close();
		oos.close();
		socket.close();
	}
}

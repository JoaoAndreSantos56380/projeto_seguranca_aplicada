/* import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
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

public class ECDHClientWithRSASignature {

	// For demonstration, generate the client's RSA key pair.
	private static KeyPair clientRSAKeyPair;
	// Assume the server's RSA public key is already trusted and exchanged.
	private static PublicKey serverRSAPublicKey;

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		// Generate or load RSA keys.
		clientRSAKeyPair = generateRSAKeyPair();
		serverRSAPublicKey = loadServerRSAPublicKey(); // Stub: implement proper key retrieval

		// Generate an ephemeral ECDH key pair.
		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDH", "BC");
		keyGen.initialize(ecSpec);
		KeyPair ecdhKeyPair = keyGen.generateKeyPair();
		byte[] ecdhPubKeyEncoded = ecdhKeyPair.getPublic().getEncoded();

		// Sign the ECDH public key using the client's RSA private key.
		byte[] signature = signData(ecdhPubKeyEncoded, clientRSAKeyPair.getPrivate());

		// Connect to the server.
		Socket socket = new Socket("localhost", 9000);
		System.out.println("Connected to ECDH server.");

		ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
		ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());

		// Receive the server's ECDH public key and RSA signature.
		byte[] serverEcdhPubKeyEncoded = (byte[]) ois.readObject();
		byte[] serverSignature = (byte[]) ois.readObject();
		System.out.println("Received server's ECDH public key and RSA signature.");

		// Verify the server's signature using the server's RSA public key.
		if (!verifySignature(serverEcdhPubKeyEncoded, serverSignature, serverRSAPublicKey)) {
			socket.close();
			throw new SecurityException("Server's RSA signature verification failed!");
		}
		System.out.println("Server's RSA signature verified.");

		// Send the client's ECDH public key and RSA signature.
		oos.writeObject(ecdhPubKeyEncoded);
		oos.writeObject(signature);
		oos.flush();
		System.out.println("Sent client's ECDH public key and RSA signature.");

		// Reconstruct the server's ECDH public key.
		KeyFactory keyFactory = KeyFactory.getInstance("ECDH", "BC");
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(serverEcdhPubKeyEncoded);
		PublicKey serverEcdhPubKey = keyFactory.generatePublic(keySpec);

		// Perform the ECDH key agreement.
		KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH", "BC");
		keyAgree.init(ecdhKeyPair.getPrivate());
		keyAgree.doPhase(serverEcdhPubKey, true);
		byte[] sharedSecret = keyAgree.generateSecret();
		System.out.println("Client computed shared secret: " + Arrays.toString(sharedSecret));

		ois.close();
		oos.close();
		socket.close();
	}

	private static KeyPair generateRSAKeyPair() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		return kpg.generateKeyPair();
	}

	private static PublicKey loadServerRSAPublicKey() throws Exception {
		// In production, load the server's RSA public key from a trusted source.
		// For demonstration, we simulate it by generating a new RSA key pair.
		KeyPair serverKeyPair = generateRSAKeyPair();
		return serverKeyPair.getPublic();
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

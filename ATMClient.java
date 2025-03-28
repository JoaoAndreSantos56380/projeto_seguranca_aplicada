import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyAgreement;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ATMClient {
	private static final String SERVER_IP = "127.0.0.1";
	private static final int SERVER_PORT = 3000;
	private static final String AUTH_FILE = "bank.auth"; // Shared auth file

	public static void main(String[] args) {
		try {
			Security.addProvider(new BouncyCastleProvider());
			KeyPair atmKeyPair = RSAKeyUtils.generateRSAKeyPair();
			// Load the shared secret key from the auth file.
			PublicKey bankPublicKey = FileUtils.readPublicKey(AUTH_FILE);
			Socket socket = new Socket(SERVER_IP, SERVER_PORT);

			SecureSocket secureSocket = new SecureSocket(socket, bankPublicKey, atmKeyPair);
			if (performHandshake(secureSocket)) {
				System.out.println("Mutual authentication successful!");
				// Further processing after authentication can follow here.
			} else {
				System.out.println("Mutual authentication failed!");
			}

			//inputValidation(args);


			socket.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	// Implements the handshake protocol.
	private static boolean performHandshake(SecureSocket secureSocket) throws Exception {
		//byte[] atmPublicKeyEncrypted = RSAKeyUtils.encryptWithPublicKey(secureSocket.bankPublicKey.getEncoded(), secureSocket.atmKeyPair.getPublic());
		byte[] atmPublicKeyEncrypted = RSAKeyUtils.encryptData(secureSocket.getKeyPair().getPublic()/* secureSocket.atmKeyPair.getPublic() */.getEncoded(), secureSocket.getBankPublicKey()/* secureSocket.bankPublicKey */);
		secureSocket.sendMessage(atmPublicKeyEncrypted);

		// Generate an ephemeral ECDH key pair.
		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDH", "BC");
		keyGen.initialize(ecSpec);
		KeyPair ecdhKeyPair = keyGen.generateKeyPair();
		byte[] ecdhPubKeyEncoded = ecdhKeyPair.getPublic().getEncoded();

		// Sign the ECDH public key using the client's RSA private key.
		byte[] signature = RSAKeyUtils.signData(ecdhPubKeyEncoded, secureSocket.getKeyPair().getPrivate()/* secureSocket.atmKeyPair.getPrivate() */);

		// Receive the server's ECDH public key and RSA signature.
		byte[] serverEcdhPubKeyEncoded = secureSocket.receiveMessage(); // (byte[]) ois.readObject();
		byte[] serverSignature = secureSocket.receiveMessage(); // (byte[]) ois.readObject();
		System.out.println("Received server's ECDH public key and RSA signature.");

		// Verify the server's signature using the server's RSA public key.
		if (!RSAKeyUtils.verifySignature(serverEcdhPubKeyEncoded, serverSignature, secureSocket.getBankPublicKey()/* secureSocket.bankPublicKey */)) {
			secureSocket.close();//secureSocket.socket.close(); // socket.close();
			throw new SecurityException("Server's RSA signature verification failed!");
		}
		System.out.println("Server's RSA signature verified.");

		// Send the client's ECDH public key and RSA signature.
		secureSocket.sendMessage(ecdhPubKeyEncoded); // oos.writeObject(ecdhPubKeyEncoded);
		secureSocket.sendMessage(signature);// oos.writeObject(signature);
		secureSocket.flush();// oos.flush();
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

		/* ois.close();
		oos.close();
		socket.close(); */


		return true;
	}

	private static void inputValidation(String[] args) {

		if (!(args == null || args.length == 0 || args.length > 4096)) {

			//THIS LOOP IS JUST TO TEST
/*
			Scanner scanner = new Scanner(System.in);
			while (true) {

				System.out.print("Enter some input: ");
				String userInput = scanner.nextLine();

				boolean value = portValidation(userInput);
				System.out.println(value);
			}*/

			//return true;
		} //else return false;

	}

	/**
	 *
	 * @param input Number part to be validated
	 * @return true if it corresponds to a number, false otherwise
	 */
	private static boolean numberValidation(String input) {
		String regex = "0|[1-9][0-9]*";

		Pattern pattern = Pattern.compile(regex);
		Matcher matcher = pattern.matcher(input);

		return matcher.matches();
	}

	/**
	 * This function is supposed to receive ONLY the FRACTIONAL part of the number
	 * example: 9487599.43 -> only the 43 passes through this function
	 *
	 * @param input fraction part of the number to be validated
	 * @return true if it corresponds to a 2 decimal place fractional number, false otherwise
	 */
	private static boolean fractionValidation (String input) {
		String regex = "[0-9]{2}";

		Pattern pattern = Pattern.compile(regex);
		Matcher matcher = pattern.matcher(input);

		return matcher.matches();
	}

	/**
	 *
	 * Does it make sense to allowa multiple "."?
	 *
	 * @param input file name to be verified
	 * @return true if it is a valid filename, false otherwise
	 */
	private static boolean fileValidation (String input) {
		if (input != null && !input.isEmpty() && input.length() <= 127) {

			String dotRegex = "^\\.$|^\\.\\.$";
			Pattern dotPattern = Pattern.compile(dotRegex);

			//if it isn't only "." ".."
			if (!dotPattern.matcher(input).matches()) {

				String regex = "^[\\-_\\.0-9a-z]+$";

				Pattern pattern = Pattern.compile(regex);
				Matcher matcher = pattern.matcher(input);

				return matcher.matches();

			}else return false;
		} else return false;
	}

	/**
	 *
	 * @param input account name to be verified
	 * @return true if it is a valid account name, false otherwise
	 */
	private static boolean accountValidation (String input) {
		if (input != null && !input.isEmpty() && input.length() <= 122) {

			String regex = "^[\\-_\\.0-9a-z]+$";

			Pattern pattern = Pattern.compile(regex);
			Matcher matcher = pattern.matcher(input);

			return matcher.matches();

		} else return false;
	}

	/**
	 *
	 * @param input ip to be verified
	 * @return true if it is a valid ip, false otherwise
	 */
	private static boolean ipValidation (String input) {
		if (input != null && !input.isEmpty() && input.length() <= 16) {

			String regex = "(\\b25[0-5]|\\b2[0-4][0-9]|\\b[01]?[0-9][0-9]?)(\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}";

			Pattern pattern = Pattern.compile(regex);
			Matcher matcher = pattern.matcher(input);

			return matcher.matches();

		} else return false;
	}

	/**
	 * Validates a port if it is between 1024 and 65535
	 *
	 * @param input port to be verified
	 * @return true if it is a valid port, false otherwise
	 */
	private static boolean portValidation (String input) {
		if (input != null && !input.isEmpty() && input.length() <= 16) {

			String regex = "^(102[4-9]|10[3-9][0-9]|1[1-9][0-9][0-9]|[2-9][0-9]{3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$";

			Pattern pattern = Pattern.compile(regex);
			Matcher matcher = pattern.matcher(input);

			return matcher.matches();
			/*
			tested with this function
			Random r = new Random();
			int temp;
			for (int i = 0; i <= 10000; i++) {
				temp = r.nextInt(1024, 65536);
				if (!portValidation(String.valueOf(temp))) {
					System.out.println("Failed for port " + temp);
				}
			}*/

		} else return false;
	}

	// SecureSocket helper class for encrypted and authenticated communication.
	/* private static class SecureSocket {
		private Socket socket;
		private ObjectInputStream in;
		private ObjectOutputStream out;
		private PublicKey bankPublicKey;
		private KeyPair atmKeyPair;

		public SecureSocket(Socket socket, PublicKey bankPublicKey, KeyPair atmKeyPair) throws IOException {
			this.socket = socket;
			this.atmKeyPair = atmKeyPair;
			this.bankPublicKey = bankPublicKey;
			this.out = new ObjectOutputStream(this.socket.getOutputStream());
			this.in = new ObjectInputStream(this.socket.getInputStream());
		}

		public SecureSocket(Socket socket) throws IOException {
			this.socket = socket;
			this.in = new ObjectInputStream(socket.getInputStream());
			this.out = new ObjectOutputStream(socket.getOutputStream());
		}

		// Encrypts, computes HMAC, and sends the message.
		public void sendMessage(String message) throws Exception {

		}

		public void sendMessage(byte[] message) throws Exception {
			this.out.writeObject(message);
		}

		public byte[] receiveMessage() throws Exception {
			return (byte[]) in.readObject();
		}

		public void close(){
			try {
				this.socket.close();
			} catch (IOException e) {
				//e.printStackTrace();
				System.out.println("senhora socket nao quis fechar");
			}
		}

		public void flush(){
			try {
				this.out.flush();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	} */
}

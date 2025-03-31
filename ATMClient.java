import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.File;
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
	private static final boolean debug = true;
	private static final int EXIT_FAILURE = 255;
	private static final String SERVER_IP = "127.0.0.1";
	private static final int SERVER_PORT = 3000;
	private static final String AUTH_FILE = "bank.auth"; // Shared auth file
	private static SecureSocket secureSocket = null;
	private static byte[] sharedSecret;

	public static void main(String[] args) {
		try {
			validateArgs(args);
			Security.addProvider(new BouncyCastleProvider());
			KeyPair atmKeyPair = RSAKeyUtils.generateRSAKeyPair();
			// Load the shared secret key from the auth file.
			PublicKey bankPublicKey = FileUtils.readPublicKey(AUTH_FILE);
			Socket socket = new Socket(SERVER_IP, SERVER_PORT);

			secureSocket = new SecureSocket(socket, bankPublicKey, atmKeyPair);
			if (performHandshake(secureSocket)) {
				System.out.println("Mutual authentication successful!");
				// Further processing after authentication can follow here.
				ECDHAESEncryption ECDHKey = new ECDHAESEncryption(sharedSecret);
				try{
					byte[] EncryptedMsg = secureSocket.receiveMessage();
					String SequenceNumber = ECDHKey.decrypt(EncryptedMsg);
					String arguments = String.join(" ", args);
					arguments = arguments + " " + SequenceNumber;
					byte[] MessageArgs = ECDHKey.encrypt(arguments);
					secureSocket.sendMessage(MessageArgs);
				}
				catch(Exception e){

				}				
			} else {
				System.out.println("Mutual authentication failed!");
			}

			socket.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	// Implements the handshake protocol.
	private static boolean performHandshake(SecureSocket secureSocket) throws Exception {
		byte[] atmPublicKeyEncrypted = RSAKeyUtils.encryptData(
				secureSocket.getKeyPair().getPublic().getEncoded(),
				secureSocket.getBankPublicKey());
		secureSocket.sendMessage(atmPublicKeyEncrypted);

		// Generate an ephemeral ECDH key pair.
		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDH", "BC");
		keyGen.initialize(ecSpec);
		KeyPair ecdhKeyPair = keyGen.generateKeyPair();
		byte[] ecdhPubKeyEncoded = ecdhKeyPair.getPublic().getEncoded();

		// Sign the ECDH public key using the client's RSA private key.
		byte[] signature = RSAKeyUtils.signData(ecdhPubKeyEncoded, secureSocket.getKeyPair().getPrivate());

		// Receive the server's ECDH public key and RSA signature.
		byte[] serverEcdhPubKeyEncoded = secureSocket.receiveMessage(); // (byte[]) ois.readObject();
		byte[] serverSignature = secureSocket.receiveMessage(); // (byte[]) ois.readObject();
		System.out.println("Received server's ECDH public key and RSA signature.");

		// Verify the server's signature using the server's RSA public key.
		if (!RSAKeyUtils.verifySignature(serverEcdhPubKeyEncoded, serverSignature,
				secureSocket.getBankPublicKey()/* secureSocket.bankPublicKey */)) {
			secureSocket.close();// secureSocket.socket.close(); // socket.close();
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
		sharedSecret = keyAgree.generateSecret();
		System.out.println("Client computed shared secret: " + Arrays.toString(sharedSecret));

		return true;
	}

	private static void validateArgs(String[] args) throws IOException {
		if (args.length < 2 || args.length > 12) {
			printUsage(debug);
			// TODO fazer saida suave: cleanExit()
			System.exit(EXIT_FAILURE);
		}

		for (int i = 0; i < args.length; i+=2) {
			if (args[i].startsWith("-s")) {
				String authFilePath = extractArg("-s", i, args);
				fileValidation(authFilePath);
			} else if (args[i].startsWith("-i")) {
				String ipAdress = extractArg("-i", i, args);
				ipValidation(ipAdress);
			} else if (args[i].startsWith("-p")) {
				String port = extractArg("-p", i, args);
				portValidation(port);

			} else if (args[i].startsWith("-c")) {
				String cardFilePath = extractArg("-c", i, args);
				fileValidation(cardFilePath);
			} else if (args[i].startsWith("-a")) {
				String account = extractArg("-a", i, args);
				accountValidation(account);
			} else if (args[i].startsWith("-n")) {
				String balance = extractArg("-n", i, args);
				balanceValidation(balance);
			} else if (args[i].startsWith("-d")) {
				String balance = extractArg("-d", i, args);
				balanceValidation(balance);
			} else if (args[i].startsWith("-w")) {
				String balance = extractArg("-w", i, args);
				balanceValidation(balance);
			} else if (args[i].startsWith("-g")) {
				if (!args[i].equals("-g")) {
					printUsage(debug);
					// TODO fazer saida suave: cleanExit()
					System.exit(EXIT_FAILURE);
				}
			} else { // Invalid argument
				printUsage(debug);
				// TODO fazer saida suave: cleanExit()
				System.exit(EXIT_FAILURE);
			}
		}
	}

	private static String extractArg(String option, int i, String[] args) {
		if (args[i].equals(option) && i + 1 >= args.length) { // -s <auth-file>
			printUsage(debug);
			// TODO fazer saida suave: cleanExit()
			System.exit(EXIT_FAILURE);
		}
		return args[i].equals(option) ? args[i + 1] : option.substring(2);
	}

	private static void balanceValidation(String input) throws IOException {
		if(!canConvertStringToDouble(input)){
			cleanExit();
		}

		double balance = Double.parseDouble(input);

		if (balance < 0.00 || balance > 4294967295.99) {
			cleanExit();
		}
	}

	private static boolean canConvertStringToDouble(String input){
		try {
			Double.parseDouble(input);
		} catch (Exception e) {
			return false;
		}
		return true;
	}

	/**
	 *
	 * Does it make sense to allowa multiple "."?
	 *
	 * @param filename file name to be verified
	 * @return true if it is a valid filename, false otherwise
	 */
	private static boolean fileValidation(String filename) throws IOException {
		if (filename == null) {
			cleanExit();
		}
		if (filename.isEmpty()) {
			cleanExit();
		}
		if (filename.length() > 127) {
			cleanExit();
		}

		// String dotRegex = "^\\.$|^\\.\\.$";
		// Pattern dotPattern = Pattern.compile(dotRegex);

		String filenameRegex = "^[\\-_\\.0-9a-z]+$";
		Pattern pattern = Pattern.compile(filenameRegex);
		Matcher matcher = pattern.matcher(filename);

		File file = new File(filename);
		if (!file.exists()) {
			System.out.print(debug ? String.format("%s: not such file\n", filename): "");
			cleanExit();
			/* printUsage(debug);
			// TODO fazer saida suave: cleanExit()
			System.exit(EXIT_FAILURE); */
		}

		return matcher.matches();
	}

	/**
	 *
	 * @param account account name to be verified
	 * @return true if it is a valid account name, false otherwise
	 */
	// TODO rever regex para aceitar "." e ".."
	private static void accountValidation(String account) throws IOException {
		if(account == null || account.isEmpty() || account.length() > 122){
			cleanExit();
		}
		String regex = "^[\\-_\\.0-9a-z]+$";

		Pattern pattern = Pattern.compile(regex);
		Matcher matcher = pattern.matcher(account);

		if(!matcher.matches()){
			cleanExit();
		}
	}

	/**
	 *
	 * @param input ip to be verified
	 * @return true if it is a valid ip, false otherwise
	 */
	private static void ipValidation(String input) {
		if(input == null || input.isEmpty() || input.length() > 16){
			cleanExit();
		}

		String regex = "(\\b25[0-5]|\\b2[0-4][0-9]|\\b[01]?[0-9][0-9]?)(\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}";

		Pattern pattern = Pattern.compile(regex);
		Matcher matcher = pattern.matcher(input);

		if(!matcher.matches()){
			cleanExit();
		}
	}

	/**
	 * Validates a port if it is between 1024 and 65535
	 *
	 * @param input port to be verified
	 * @return true if it is a valid port, false otherwise
	 */
	private static void portValidation(String input) {
		if(!canConvertStringToInt(input)) {
			cleanExit();
		}

		int port = Integer.parseInt(input);
		if (port < 1024 || port > 65535) {
			cleanExit();
		}
	}

	private static boolean canConvertStringToInt(String str) {
		try {
			Integer.parseInt(str);
		} catch (Exception e) {
			return false;
		}
		return true;
	}

	private static void printUsage(boolean verbose) {
		System.out.println("Usage: ATMClient [-s <auth-file>] [-i <ip-address>] [-p <port>]");
		System.out.println("                 [-c <card-file>] -a <account> -n <balance>");
		System.out.println("Options:");
		System.out.println("  -s <auth-file>   : Authentication file (default: bank.auth)");
		System.out.println("  -i <ip-address>  : Server IP address (default: 127.0.0.1)");
		System.out.println("  -p <port>        : Server port (default: 3000)");
		System.out.println("  -c <card-file>   : Card file (default: <account>.card)");
		System.out.println("  -a <account>     : Account name (required)");
		System.out.println("  -n <balance>     : Create new account with balance amount (format: XX.XX)");
		System.out.println("  -d <balance>     : Deposit balance amount (format: XX.XX)");
		System.out.println("  -w <balance>     : Withdraw balance amount (format: XX.XX)");
		System.out.println("  -g				 : Get balance amount (format: XX.XX)");
	}

	private static void cleanExit() {
			printUsage(debug);
			if (secureSocket.isClosed()) {
				//nao eh necessario mas eh uma boa pratica
				secureSocket.closeStreams();
				secureSocket.close();
			}
			System.exit(EXIT_FAILURE);
	}
}

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
	private static final boolean verbose = false;

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
					System.out.println("Sent: " + arguments + ", to the server!");
				}
				catch(Exception e){

				}				
			} else {
				System.out.println("Mutual authentication failed!");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		cleanExit();
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

	private static boolean validateArgs(String[] args) throws IOException {
		if (args.length < 2 || args.length > 12) {
			if (verbose) printUsage();

			cleanExit();
			return false;
		}

		for (int i = 0; i < args.length; i+=2) {
			if (args[i].startsWith("-s")) {
				String authFilePath = extractArg("-s", i, args);
				if (!fileValidation(authFilePath)) cleanExit(); return false;
			} else if (args[i].startsWith("-i")) {
				String ipAddress = extractArg("-i", i, args);
				if (!ipValidation(ipAddress)) cleanExit(); return false;
			} else if (args[i].startsWith("-p")) {
				String port = extractArg("-p", i, args);
				if (!portValidation(port)) cleanExit(); return false;
			} else if (args[i].startsWith("-c")) {
				String cardFilePath = extractArg("-c", i, args);
				if (!fileValidation(cardFilePath)) cleanExit(); return false;
			} else if (args[i].startsWith("-a")) {
				String account = extractArg("-a", i, args);
				if (!accountValidation(account)) cleanExit(); return false;
			} else if (args[i].startsWith("-n")) {
				String balance = extractArg("-n", i, args);
				if (!balanceValidation(balance)) cleanExit(); return false;
			} else if (args[i].startsWith("-d")) {
				String balance = extractArg("-d", i, args);
				if (!balanceValidation(balance)) cleanExit(); return false;
			} else if (args[i].startsWith("-w")) {
				String balance = extractArg("-w", i, args);
				if (!balanceValidation(balance)) cleanExit(); return false;
			} else if (args[i].startsWith("-g")) {
				if (!args[i].equals("-g")) {
					if (verbose) printUsage(); cleanExit();
				}
			} else { // Invalid argument
				if (verbose) printUsage(); cleanExit();
			}
		}
		return false;
	}

	private static String extractArg(String option, int i, String[] args) {
		if (args[i].equals(option) && i + 1 >= args.length) { // -s <auth-file>
			//printUsage();
			cleanExit();
		}
		return args[i].equals(option) ? args[i + 1] : option.substring(2);
	}

	private static boolean balanceValidation(String input) {
		if(!canConvertStringToDouble(input)){
			return false;
		}

		double balance = Double.parseDouble(input);

		return !(balance < 0.00 || balance > 4294967295.99);
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
	private static boolean fileValidation(String filename) {
		if (filename == null || filename.isEmpty() || filename.length() > 127) {
			cleanExit();
		} else {
			String filenameRegex = "^[\\-_\\.0-9a-z]+$";
			Pattern pattern = Pattern.compile(filenameRegex);
			Matcher matcher = pattern.matcher(filename);

			File file = new File(filename);
			if (!file.exists()) {
				System.out.print(debug ? String.format("%s: no such file\n", filename) : "");
				cleanExit();
			}
			return matcher.matches();
		}
		return false;
	}

	/**
	 *
	 * @param account account name to be verified
	 * @return true if it is a valid account name, false otherwise
	 */
	// TODO rever regex para aceitar "." e ".."
	private static boolean accountValidation(String account) throws IOException {
		if(account == null || account.isEmpty() || account.length() > 122){
			return false;
		}
		String regex = "^[\\-_\\.0-9a-z]+$";

		Pattern pattern = Pattern.compile(regex);
		Matcher matcher = pattern.matcher(account);

		return matcher.matches();
	}

	/**
	 *
	 * @param input ip to be verified
	 * @return true if it is a valid ip, false otherwise
	 */
	private static boolean ipValidation(String input) {
		if(input == null || input.isEmpty() || input.length() > 16){
			cleanExit();
			return false;
		}

		String regex = "(\\b25[0-5]|\\b2[0-4][0-9]|\\b[01]?[0-9][0-9]?)(\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}";

		Pattern pattern = Pattern.compile(regex);
		Matcher matcher = pattern.matcher(input);

		return matcher.matches();
	}

	/**
	 * Validates a port if it is between 1024 and 65535
	 *
	 * @param input port to be verified
	 * @return true if it is a valid port, false otherwise
	 */
	private static boolean portValidation(String input) {
		if (!canConvertStringToInt(input)) {
			cleanExit();
			return false;
		}
		int port = Integer.parseInt(input);
		return port < 1024 || port > 65535;
	}

	private static boolean canConvertStringToInt(String str) {
		try {
			Integer.parseInt(str);
		} catch (Exception e) {
			return false;
		}
		return true;
	}

	private static void printUsage() {
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

	// enviar msg ao server de q este cliente fechou?
	private static void cleanExit() {
			//printUsage();
			if (secureSocket.isClosed()) {
				//nao eh necessario mas eh uma boa pratica
				//secureSocket.closeStreams();
				secureSocket.close();
			}
			System.exit(EXIT_FAILURE);
	}
}

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.File;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ATMClient {
	private static final boolean debug = true;
	private static final int EXIT_FAILURE = 255;
	private static final String SERVER_IP = "127.0.0.1";
	private static final int SERVER_PORT = 3000;
	private static final String AUTH_FILE = "bank.auth"; // Shared auth file
	private static final String CARD_FILE = "card.file"; // Shared auth file

	private static final boolean verbose = false;

	private byte[] sharedSecret;
	private ATMConfig config;
	private SecureSocket secureSocket = null;

	public static void main(String[] args) {
		new ATMClient(args);
	}

	public ATMClient(String[] args) {
		if (!isValidArgs(args)) {
			cleanExit();
		}

		config = getConfigFromArgs(args);

		addShutdownHook();

		// init()
		try {
			Security.addProvider(new BouncyCastleProvider());
			KeyPair atmKeyPair = RSAKeyUtils.generateRSAKeyPair();
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(128);
			SecretKey secretKey = keyGen.generateKey();

			FileUtils.saveClientPin(secretKey, "card.file");
			// Load the shared secret key from the auth file.
			PublicKey bankPublicKey = FileUtils.readPublicKey(AUTH_FILE);
			Socket socket = new Socket(SERVER_IP, SERVER_PORT);

			if (socket.isClosed() || !socket.isConnected()) {
				System.out.println("ERROR: socket is not connected");
				cleanExit();
			}

			secureSocket = new SecureSocket(socket, bankPublicKey, atmKeyPair);
			if (performHandshake(secureSocket)) {
				System.out.println("Mutual authentication successful!");
				// Further processing after authentication can follow here.
				ECDHAESEncryption ECDHKey = new ECDHAESEncryption(sharedSecret);
				try {
					byte[] EncryptedMsg = secureSocket.receiveMessage();
					String SequenceNumber = ECDHKey.decrypt(EncryptedMsg);
					String arguments = String.join(" ", args);
					arguments = arguments + " " + SequenceNumber;
					byte[] MessageArgs = ECDHKey.encrypt(arguments);
					secureSocket.sendMessage(MessageArgs);
					System.out.println("Sent: " + arguments + ", to the server!");
				} catch (Exception e) {

				}
			} else {
				System.out.println("Mutual authentication failed!");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		run(args);
	}

// Implements the handshake protocol.
private boolean performHandshake(SecureSocket secureSocket) throws Exception {
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
	//System.out.println(sharedSecret.length);

	return true;
}

	private boolean isValidArgs(String[] args) {
		if (args.length < 2 || args.length > 12) {
			if (verbose)
				printUsage();
			return false;
		}
		// Set to track duplicate arguments
		Set<String> usedArgs = new HashSet<>();

		for (int i = 0; i < args.length; i++) {

			// Check for duplicate argument
			if (usedArgs.contains(args[i])) {
				if (verbose) System.out.println("Error: Duplicate argument " + args[i]);
				return false;
			}

			if (args[i].startsWith("-s")) {
				String authFilePath = extractArg("-s", i, args);
				if (authFilePath == null || !isValidAuthFile(authFilePath))
					return false;
				if (args[i].equals("-s")) {
					i++;
				}
			} else if (args[i].startsWith("-i")) {
				String ipAddress = extractArg("-i", i, args);
				if (ipAddress == null || !isValidIp(ipAddress))
					return false;
				if (args[i].equals("-i")) {
					i++;
				}
			} else if (args[i].startsWith("-p")) {
				String port = extractArg("-p", i, args);
				if (port == null || !isValidPort(port))
					return false;
				if (args[i].equals("-p")) {
					i++;
				}
			} else if (args[i].startsWith("-c")) {
				String cardFilePath = extractArg("-c", i, args);
				if (cardFilePath == null || !isValidCardFile(cardFilePath))
					return false;
				if (args[i].equals("-c")) {
					i++;
				}
			} else if (args[i].startsWith("-a")) {
				String account = extractArg("-a", i, args);
				if (account == null || !isValidAccount(account))
					return false;
				if (args[i].equals("-a")) {
					i++;
				}
			} else if (args[i].startsWith("-n")) {
				String balance = extractArg("-n", i, args);
				if (balance == null || !isValidBalance(balance))
					return false;
				if (args[i].equals("-n")) {
					i++;
				}
			} else if (args[i].startsWith("-d")) {
				String balance = extractArg("-d", i, args);
				if (balance == null || !isValidBalance(balance))
					return false;
				if (args[i].equals("-d")) {
					i++;
				}
			} else if (args[i].startsWith("-w")) {
				String balance = extractArg("-w", i, args);
				if (balance == null || !isValidBalance(balance))
					return false;
				if (args[i].equals("-w")) {
					i++;
				}
			} else if (args[i].startsWith("-g")) {
				if (!args[i].equals("-g")) {
					if (verbose)
						printUsage();
				}
			} else { // Invalid argument
				if (verbose)
					printUsage();
			}
			usedArgs.add(args[i]);
		}
		return true;
	}

	private String extractArg(String option, int i, String[] args) {
		if (args[i].equals(option) && i + 1 >= args.length) { // -s <auth-file>
			return null;
		}
		return args[i].equals(option) ? args[i + 1] : option.substring(2);
	}

	private boolean isValidBalance(String input) {

		if (!canConvertStringToDouble(input)) {
			return false;
		}

		double balanceDouble = Double.parseDouble(input);
		//work with Longs * 100 instead of doubles
		long balance = (long) (balanceDouble * 100);

		return !(balance < 0 || balance > 429496729599L);
	}

	private boolean canConvertStringToDouble(String input) {
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
	private boolean isValidAuthFile(String filename) {
		if (filename == null || filename.isEmpty() || filename.length() > 127) {
			cleanExit();
		} else {
			String filenameRegex = "^[\\-_\\.0-9a-z]+$";
			Pattern pattern = Pattern.compile(filenameRegex);
			Matcher matcher = pattern.matcher(filename);

			File file = new File(filename);
			if (!file.exists()) {
				System.out.print(debug ? String.format("%s: no such file\n", filename) : "");
			}
			return matcher.matches();
		}
		return false;
	}

	/**
	 *
	 * Does it make sense to allowa multiple "."?
	 *
	 * @param filename file name to be verified
	 * @return true if it is a valid filename, false otherwise
	 */
	private boolean isValidCardFile(String filename) {
		if (filename == null || filename.isEmpty() || filename.length() > 127) {
			cleanExit();
		}
		String filenameRegex = "^[\\-_\\.0-9a-z]+$";
		Pattern pattern = Pattern.compile(filenameRegex);
		Matcher matcher = pattern.matcher(filename);

		return matcher.matches();
	}

	/**
	 *
	 * @param account account name to be verified
	 * @return true if it is a valid account name, false otherwise
	 */
	// TODO rever regex para aceitar "." e ".."
	private boolean isValidAccount(String account) {
		if (account == null || account.isEmpty() || account.length() > 122) {
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
	private boolean isValidIp(String input) {
		if (input == null || input.isEmpty() || input.length() > 16) {
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
	private boolean isValidPort(String input) {
		if (!canConvertStringToInt(input)) {
			return false;
		}
		int port = Integer.parseInt(input);
		return port >= 1024 && port <= 65535;
	}

	private boolean canConvertStringToInt(String str) {
		try {
			Integer.parseInt(str);
		} catch (Exception e) {
			return false;
		}
		return true;
	}

	private ATMConfig getConfigFromArgs(String[] args) {
		config = new ATMConfig(AUTH_FILE, SERVER_IP, SERVER_PORT);

		for (int i = 0; i < args.length; i++) {
			if (args[i].startsWith("-s")) {
				config.authFile = extractArg("-s", i, args);
				if (args[i].equals(AUTH_FILE)) {
					i++;
				}
			} else if (args[i].startsWith("-i")) {
				config.serverPort = Integer.parseInt(extractArg("-i", i, args));
				if (args[i].equals("-i")) {
					i++;
				}
			} else if (args[i].startsWith("-p")) {
				config.serverPort = Integer.parseInt(extractArg("-p", i, args));
				if (args[i].equals("-p")) {
					i++;
				}
			} else if (args[i].startsWith("-a")) {
				String account = extractArg("-a", i, args);
				config.account = account;
				if(config.cardFile == null) {
					config.cardFile = account + ".card";
				}
				if (args[i].equals("-a")) {
					i++;
				}
			} else if (args[i].startsWith("-c")) {
				String card = extractArg("-c", i, args);
				config.cardFile = card;
				if (args[i].equals("-c")) {
					i++;
				}
			}
		}

		return config;
	}

	private void init() {
	}

	private void run(String[] args) {

		//TROCAR PARA INT * 100
		//int balance;
		double balance = 0;

		for (int i = 0; i < args.length; i++) {
			if (args[i].startsWith("-n")) {
				System.out.println(extractArg("-n", i, args));
				balance = Double.parseDouble(extractArg("-n", i, args));
				if (args[i].equals("-n")) {
					i++;
				}
				// createAccount(balance);
				return;
			} else if (args[i].startsWith("-d")) {
				//balance = Integer.parseInt(extractArg("-d", i, args));
				balance = Double.parseDouble(extractArg("-n", i, args));
				if (args[i].equals("-d")) {
					i++;
				}
				// deposit(balance);
				return;
			} else if (args[i].startsWith("-w")) {
				balance = Double.parseDouble(extractArg("-n", i, args));
				if (args[i].equals("-w")) {
					i++;
				}
				// withdraw(balance);
				return;
			} else if (args[i].startsWith("-g")) {
				// get();
				return;
			}
		}
		//encerrar o cliente
		//cleanExit();
		//System.exit(0);
	}

	private void printUsage() {
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
	private void cleanExit() {
		// printUsage();
		if (secureSocket != null && secureSocket.isClosed()) {
			secureSocket.close();
		}
		System.exit(EXIT_FAILURE);
	}

	private class ATMConfig {
		public String authFile;
		public String serverIp;
		public int serverPort;
		public String cardFile;
		public String account;

		ATMConfig(String authFile, String serverIp, int serverPort) {
			this.authFile = authFile;
			this.serverIp = serverIp;
			this.serverPort = serverPort;
		}

		@Override
		public String toString() {
			return String.format("ATMConfig[authFile=%s, serverIp=%s, serverPort=%d, cardFile=%s, account=%s]",
				authFile, serverIp, serverPort, cardFile, account);
		}
	}

	private void addShutdownHook() {
		ClientShutdown shutdownThread = new ClientShutdown();
		Runtime.getRuntime().addShutdownHook(shutdownThread);
	}

	class ClientShutdown extends Thread {
		public void run() {
			cleanExit();
		}
	}
}



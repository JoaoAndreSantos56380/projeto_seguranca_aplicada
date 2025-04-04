import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.File;
import java.io.FileOutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
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
	private static final int EXIT_SUCCESS = 0;
	private static final String SERVER_IP = "127.0.0.1";
	private static final int SERVER_PORT = 3000;
	private static final String DEFAULT_AUTH_FILE = "bank.auth"; // Shared auth file
	private static final String CARD_FILE = "card.file"; // Shared auth file

	private static final boolean verbose = false;

	private byte[] sharedSecret;
	private ATMConfig config;
	ClientAccount account;
	private SecureSocket secureSocket = null;

	public static void main(String[] args) {
		new ATMClient(args);
	}

	public ATMClient(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		if (!isValidArgs(args)) {
			cleanExit();
		}

		config = getConfigFromArgs(args);
		account = getAccount(args);
		Connection connection = getServerConnection();

		KeyPair atmKeyPair = generateKeyPair();
		byte[] encryptedAtmPublicKey = encryptKey(atmKeyPair.getPublic(), config.bankPublicKey);
		connection.send(encryptedAtmPublicKey);

		syncSessionKeys(connection, atmKeyPair, config.bankPublicKey);

		// remover depois pk isto e um mock
		ECDHAESEncryption ECDHKey = getAESKeyFromSharesSecret();

		// Obter número de sequência do servidor
		int sequenceNumber = getSequenceNumber(connection.receive(), ECDHKey);

		Operation op = getOperation(args);
		// Gerar mensagem consoante args, com número de sequência
		MessageWithSequenceNumber messageToEncrypt = new MessageWithSequenceNumber(new Message(account, op),
				sequenceNumber+1);
		// Encriptar mensagem com chave de sessão
		byte[] encryptedMessage = encryptMessage(messageToEncrypt, ECDHKey);
		// Enviar mensagem encriptada
		connection.send(encryptedMessage);
		// Obter "OK" ou "NOK"
		Reply reply = (Reply) Reply.fromByteArray(connection.receive());
		System.out.println(reply.status);
		// Exit
		//System.out.println("leaving...");
		// init(args);
		// run(args);
	}

	private byte[] encryptMessage(MessageWithSequenceNumber messageToEncrypt, ECDHAESEncryption ECDHKey) {
		byte[] encryptedMessage = null;
		try {
			byte[] bytes = messageToEncrypt.toByteArray();
			encryptedMessage = ECDHKey.encrypt(bytes);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return encryptedMessage;
	}

	private Operation getOperation(String[] args) {
		for (int i = 0; i < args.length; i++) {
			if (args[i].startsWith("-n")) {
				String balance = extractArg("-n", i, args);
				return new Operation(Operations.NEW_ACCOUNT, Double.parseDouble(balance));
			} else if (args[i].startsWith("-d")) {
				String balance = extractArg("-d", i, args);
				return new Operation(Operations.DEPOSIT, Double.parseDouble(balance));
			} else if (args[i].startsWith("-w")) {
				String balance = extractArg("-w", i, args);
				return new Operation(Operations.WITHDRAW, Double.parseDouble(balance));
			} else if (args[i].startsWith("-g")) {
				return new Operation(Operations.NEW_ACCOUNT, -1);
			}
		}
		return null;
	}

	private ECDHAESEncryption getAESKeyFromSharesSecret() {
		ECDHAESEncryption ECDHKey = null;
		try {
			ECDHKey = new ECDHAESEncryption(sharedSecret);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return ECDHKey;
	}

	private int getSequenceNumber(byte[] EncryptedMsg, ECDHAESEncryption ECDHKey) {
		byte[] bytes = null;
		try {
			bytes = ECDHKey.decrypt(EncryptedMsg);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return ByteBuffer.wrap(bytes).getInt();
	}

	private byte[] encryptKey(PublicKey publicKey, PublicKey bankPublicKey) {
		byte[] ATM_PublicKey = publicKey.getEncoded();
		byte[] atmPublicKeyEncrypted = RSAKeyUtils.encryptData(ATM_PublicKey, bankPublicKey);
		return atmPublicKeyEncrypted;
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
				if (verbose)
					System.out.println("Error: Duplicate argument " + args[i]);
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
		// work with Longs * 100 instead of doubles
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
		config = new ATMConfig(DEFAULT_AUTH_FILE, SERVER_IP, SERVER_PORT);

		addShutdownHook();

		for (int i = 0; i < args.length; i++) {
			if (args[i].startsWith("-s")) {
				config.serverAuthFile = extractArg("-s", i, args);
				if (args[i].equals("-s")) {
					i++;
				}
			} else if (args[i].startsWith("-i")) {
				config.serverIp = extractArg("-i", i, args);
				if (args[i].equals("-i")) {
					i++;
				}
			} else if (args[i].startsWith("-p")) {
				config.serverPort = Integer.parseInt(extractArg("-p", i, args));
				if (args[i].equals("-p")) {
					i++;
				}
			}
		}

		return config;
	}

	private ClientAccount getAccount(String[] args) {
		account = new ClientAccount();

		String accountPINFilename = null;

		for (int i = 0; i < args.length; i++) {
			if (args[i].startsWith("-a")) {
				String name = extractArg("-a", i, args);
				account.name = name;
				if (accountPINFilename == null) {
					accountPINFilename = name + ".card";
				}
				if (args[i].equals("-a")) {
					i++;
				}
			} else if (args[i].startsWith("-c")) {
				String PINfilename = extractArg("-c", i, args);
				accountPINFilename = PINfilename;
				if (args[i].equals("-c")) {
					i++;
				}
			}
		}

		account.PIN = getAccountPIN(accountPINFilename);
		if (account.PIN == null) {
			SecretKey key = generateAESkey();
			if (key != null) {
				try (FileOutputStream out = new FileOutputStream(accountPINFilename)) {
					out.write(key.getEncoded());
					out.flush();
					account.PIN = getAccountPIN(accountPINFilename);
					System.out.println("File created and data written.");
				} catch (IOException e) {
					System.out.println("An error occurred.");
					e.printStackTrace();
				}
			}
		}

		return account;
	}

	private byte[] getAccountPIN(String filePath) {
		Path path = Paths.get(filePath);
		byte[] bytes = null;
		try {
			bytes = Files.readAllBytes(path);
		} catch (IOException e) {
			return null;
			// e.printStackTrace();
		}
		return bytes;
	}

	private SecretKey generateAESkey() {
		KeyGenerator keyGen;
		SecretKey secretKey = null;
		try {
			keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(128);
			secretKey = keyGen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return secretKey;
	}

	private Connection getServerConnection() {
		Connection connection = null;
		try {
			Socket socket = new Socket(SERVER_IP, SERVER_PORT);
			connection = new Connection(socket);
			System.out.println("aqui");
		} catch (Exception e) {
			e.printStackTrace();
		}
		return connection;
	}

	private KeyPair generateKeyPair() {
		KeyPair keyPair = null;
		try {
			keyPair = RSAKeyUtils.generateRSAKeyPair();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return keyPair;
	}

	private byte[] getAtmPublicKey() {
		KeyPair atmKeyPair = null;
		PublicKey bankPublicKey;
		try {
			atmKeyPair = RSAKeyUtils.generateRSAKeyPair();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		bankPublicKey = FileUtils.readPublicKey(DEFAULT_AUTH_FILE);
		byte[] ATM_PublicKey = atmKeyPair.getPublic().getEncoded();
		byte[] atmPublicKeyEncrypted = RSAKeyUtils.encryptData(ATM_PublicKey, bankPublicKey);
		return atmPublicKeyEncrypted;
	}

	private void syncSessionKeys(Connection connection, KeyPair atmKeyPair, PublicKey bankPublicKey) {
		try {
			// Security.addProvider(new BouncyCastleProvider());
			// Generate an ephemeral ECDH key pair.
			ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDH", "BC");
			keyGen.initialize(ecSpec);
			KeyPair ecdhKeyPair = keyGen.generateKeyPair();
			byte[] ecdhPubKeyEncoded = ecdhKeyPair.getPublic().getEncoded();

			// Sign the ECDH public key using the client's RSA private key.
			byte[] signature = RSAKeyUtils.signData(ecdhPubKeyEncoded, atmKeyPair.getPrivate());

			// Receive the server's ECDH public key and RSA signature.
			byte[] serverEcdhPubKeyEncoded = connection.receive(); // (byte[]) ois.readObject();
			byte[] serverSignature = connection.receive(); // (byte[]) ois.readObject();
			System.out.println("Received server's ECDH public key and RSA signature.");

			// Verify the server's signature using the server's RSA public key.
			if (!RSAKeyUtils.verifySignature(serverEcdhPubKeyEncoded, serverSignature, bankPublicKey)) {
				connection.close();// secureSocket.socket.close(); // socket.close();
				throw new SecurityException("Server's RSA signature verification failed!");
			}
			System.out.println("Server's RSA signature verified.");

			// Send the client's ECDH public key and RSA signature.
			connection.send(ecdhPubKeyEncoded); // oos.writeObject(ecdhPubKeyEncoded);
			connection.send(signature);// oos.writeObject(signature);
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
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/*
	 * private void init(String[] args) {
	 * try {
	 * Security.addProvider(new BouncyCastleProvider());
	 * KeyGenerator keyGen = KeyGenerator.getInstance("AES");
	 * keyGen.init(128);
	 * SecretKey secretKey = keyGen.generateKey();
	 *
	 * FileUtils.saveClientPIN(secretKey, "card.file");
	 * // Load the shared secret key from the auth file.
	 * PublicKey bankPublicKey = FileUtils.readPublicKey(DEFAULT_AUTH_FILE);
	 * Socket socket = new Socket(SERVER_IP, SERVER_PORT);
	 *
	 * if (socket.isClosed() || !socket.isConnected()) {
	 * System.out.println("ERROR: socket is not connected");
	 * cleanExit();
	 * }
	 *
	 * secureSocket = new SecureSocket(socket, bankPublicKey, atmKeyPair);
	 * if (syncSessionKeys(secureSocket)) {
	 * System.out.println("Mutual authentication successful!");
	 * // Further processing after authentication can follow here.
	 * ECDHAESEncryption ECDHKey = new ECDHAESEncryption(sharedSecret);
	 * } else {
	 * System.out.println("Mutual authentication failed!");
	 * }
	 * } catch (Exception e) {
	 * e.printStackTrace();
	 * }
	 *
	 * // run(args);
	 * try {
	 * String json = secureSocket.receiveStringMessage();
	 * successfullExit(json);
	 * } catch (Exception e) {
	 * cleanExit();
	 * }
	 * }
	 */

	private void run(String[] args) {

		// TROCAR PARA INT * 100
		// int balance;
		double balance = 0;

		for (int i = 0; i < args.length; i++) {
			if (args[i].startsWith("-n")) {
				System.out.println(extractArg("-n", i, args));
				balance = Double.parseDouble(extractArg("-n", i, args));
				if (args[i].equals("-n")) {
					i++;
				}
				createAccount(balance);
				return;
			} else if (args[i].startsWith("-d")) {
				// balance = Integer.parseInt(extractArg("-d", i, args));
				balance = Double.parseDouble(extractArg("-d", i, args));
				if (args[i].equals("-d")) {
					i++;
				}
				// deposit(balance);
				return;
			} else if (args[i].startsWith("-w")) {
				balance = Double.parseDouble(extractArg("-w", i, args));
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
	}

	private void createAccount(double balance) {

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

	private void successfullExit(String json) {
		if (secureSocket != null && secureSocket.isClosed()) {
			secureSocket.close();
		}
		// print the operation
		System.out.println(json);
		System.exit(EXIT_SUCCESS);
	}

	private class ATMConfig {
		public String serverAuthFile;
		public String serverIp;
		public int serverPort;
		public PublicKey bankPublicKey;

		ATMConfig(String authFile, String serverIp, int serverPort) {
			this.serverAuthFile = authFile;
			this.serverIp = serverIp;
			this.serverPort = serverPort;
			bankPublicKey = FileUtils.readPublicKey(serverAuthFile);
		}

		@Override
		public String toString() {
			return String.format("ATMConfig[authFile=%s, serverIp=%s, serverPort=%d]",
					serverAuthFile, serverIp, serverPort);
		}
	}

	private void addShutdownHook() {
		Runtime.getRuntime().addShutdownHook(new Thread(() -> {
			System.out.println("\nShutdown signal received. Cleaning up...");
			cleanExit();
			System.out.println("Shutdown complete.");
		}));
	}
}

import java.io.*;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.security.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class BankServer {
	// Constants
	private static final boolean debug = false;
	private static final String ARGS_AUTH_FILE = "-s";
	private static final String DEFAULT_AUTH_FILE = "bank.auth";
	private static final String ARGS_PORT = "-p";
	private static final int DEFAULT_PORT = 3000;
	private static final int EXIT_FAILURE = 255;
	private static final int PROTOCOL_ERROR = 63;
	private static int ERROR;
	private static final int EXIT_SUCCESS = 0;

	// Attributes
	private ServerConfig config;
	private ServerSocket serverSocket;
	private KeyPair rsaKeyPair;
	private final SecureRandom random = new SecureRandom();
	private int sequenceNumber = genSeq();
	private HashMap<String, Account> accounts;

	public static void main(String[] args) throws IOException {
		new BankServer(args);
	}

	public BankServer(String[] args) {

		addShutdownHook();

		Security.addProvider(new BouncyCastleProvider());
		if (!isValidArgs(args)) {
			ERROR = EXIT_FAILURE;
			System.exit(EXIT_FAILURE);
		}

		config = getConfigFromArgs(args);

		rsaKeyPair = createAuthFileAndKeyPair();
		// criar set de contas
		accounts = createAccountset();// new HashMap<>();

		lauchServerSocketAndThreads();
	}

	private void lauchServerSocketAndThreads() {
		try {
			// eh siupsoto aceitarmos apenas de um porto??
			serverSocket = new ServerSocket(config.port);

			// serverSocket.setReuseAddress(true);
			// serverSocket.bind(new InetSocketAddress(config.port));

			System.out.println("Bank server listening on port " + config.port);
			// Continuously accept client connections
			// Socket clientSocket = serverSocket.accept();

			while (!serverSocket.isClosed()) {
				Socket clientSocket = serverSocket.accept();
				System.out.println("Accepted connection from " + clientSocket.getInetAddress());
				new Thread(new ConnectionHandler(clientSocket, rsaKeyPair)).start();
			}

		} catch (Exception e) {
			cleanExit();
		}
	}

	private KeyPair createAuthFileAndKeyPair() {
		KeyPair rsaKeyPair;
		try {
			rsaKeyPair = RSAKeyUtils.generateRSAKeyPair();
			FileUtils.savePublicKey(rsaKeyPair.getPublic(), config.authFile);
			return rsaKeyPair;
		} catch (NoSuchAlgorithmException | IOException e) {
			e.printStackTrace();
			return null;
		}

	}

	private HashMap<String, Account> createAccountset() {
		return new HashMap<>();
	}

	/**
	 * This function returns true if all of its arguments are valid or false if any
	 * aren't
	 *
	 * @param args args from atm start
	 */
	private boolean isValidArgs(String[] args) {
		if (args.length > 4) {
			ERROR = EXIT_FAILURE;
			System.exit(EXIT_FAILURE);
		}

		for (int i = 0; i < args.length; i++) {
			if (args[i].startsWith(ARGS_AUTH_FILE)) {
				String authFilePath = extractArg(ARGS_AUTH_FILE, i, args);
				if (!isValidFile(authFilePath))
					return false;
				if (args[i].equals(ARGS_AUTH_FILE)) {
					i++;
				}
			} else if (args[i].startsWith(ARGS_PORT)) {
				String port = extractArg(ARGS_PORT, i, args);
				if (!isValidPort(port))
					return false;
				if (args[i].equals(ARGS_PORT)) {
					i++;
				}
			} else { // Invalid argument
				//printUsage(debug);
			}
		}

		return true;
	}

	private boolean isValidFile(String filename) {
		if (filename == null || filename.isEmpty() || filename.length() > 127) {
			return false;
		}

		String filenameRegex = "^[\\-_\\.0-9a-z]+$";
		Pattern pattern = Pattern.compile(filenameRegex);
		Matcher matcher = pattern.matcher(filename);
		if (!matcher.matches()) {
			return false;
		}

		File file = new File(filename);
		return !file.exists();
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

	private ServerConfig getConfigFromArgs(String[] args) {

		// O ficheiro nao pode estar la, tem de ser criado a cada execucao
		File file = new File(DEFAULT_AUTH_FILE);
		if (file.exists()) {
			cleanExit();
		}

		config = new ServerConfig(DEFAULT_AUTH_FILE, DEFAULT_PORT);

		for (int i = 0; i < args.length; i++) {
			if (args[i].startsWith("-s")) {
				config.authFile = extractArg("-s", i, args);
				if (args[i].equals(ARGS_AUTH_FILE)) {
					i++;
				}
			} else if (args[i].startsWith("-p")) {
				config.port = Integer.parseInt(extractArg("-p", i, args));
				if (args[i].equals(ARGS_AUTH_FILE)) {
					i++;
				}
			}
		}

		return config;
	}

	public int genSeq() {
		SecureRandom random = new SecureRandom();
		return random.nextInt(100000, 999999);
	}

	// Handles a client connection and performs the handshake.
	private class ConnectionHandler implements Runnable {
		private Socket socket;
		private KeyPair keyPair;
		private Connection connection;
		private PublicKey atmPublicKey;
		private byte[] sharedSecret = null;

		public ConnectionHandler(Socket socket, KeyPair keyPair) {
			this.socket = socket;
			this.keyPair = keyPair;
		}

		/**
		 * This is called after validation
		 */
		public void run() {
			// to be in scope of the finally block
			String json = "ola";

			try {
				connection = new Connection(socket);
				// secureSocket = new SecureSocket(socket, keyPair);
				getClientPublicKey();
				syncSessionKeys();
				if (sharedSecret != null) {
					System.out.println("Mutual authentication successful with " + socket.getInetAddress());
					// Further processing (e.g., transaction handling) would follow here
					ECDHAESEncryption ECDHKey = getAESKeyFromSharesSecret();
					// Send Sequential Number
					sendSequenctialNumber(ECDHKey);

					//socket.setSoTimeout(10000);
					//System.out.println("Setted timeout");

					MessageWithSequenceNumber msgWithSeq = receiveMessage(ECDHKey);

					processRequest(msgWithSeq);
				} else {
					System.out.println("Mutual authentication failed with " + socket.getInetAddress());
				}
			} finally {
				// fechar socket cliente
				try {
					// secureSocket.sendMessage(json);
					connection.send(json.getBytes());
					socket.close();

				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}

		private void processRequest(MessageWithSequenceNumber msgWithSeq) {
			if ((msgWithSeq.sequenceNumber) != (sequenceNumber + 1)) {
				Reply reply = new Reply(Status.NOT_OK);
				try {
					connection.send(reply.toByteArray());
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			} else {
				if (msgWithSeq.message.operation.op == Operations.NEW_ACCOUNT) {
					if (msgWithSeq.message.operation.balance < 10.0) {
						Reply reply = new Reply(Status.NOT_OK);
						try {
							connection.send(reply.toByteArray());
						} catch (IOException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
					accounts.put(msgWithSeq.message.account.name,
							new Account(msgWithSeq.message.account.name,
									msgWithSeq.message.account.PIN,
									msgWithSeq.message.operation.balance));
					try {
						connection.send(new Reply(Status.OK).toByteArray());
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			}
		}

		private MessageWithSequenceNumber receiveMessage(ECDHAESEncryption ECDHKey) {
			byte[] bytes = connection.receive();
			return decryptMessage(bytes, ECDHKey);
		}

		private void sendSequenctialNumber(ECDHAESEncryption ECDHKey) {
			byte[] EncryptedMessageSend = null;
			try {
				EncryptedMessageSend = ECDHKey.encrypt(ByteBuffer.allocate(4).putInt(sequenceNumber).array());
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			System.out.println(sequenceNumber);
			connection.send(EncryptedMessageSend);
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

		private void syncSessionKeys() {
			try {
				ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
				KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");
				keyPairGenerator.initialize(ecSpec);
				KeyPair ecdhKeyPair = keyPairGenerator.generateKeyPair();
				// Get the encoded form of the ECDH public key.
				byte[] ecdhPubKeyEncoded = ecdhKeyPair.getPublic().getEncoded();

				// Sign the ECDH public key using the server's RSA private key.
				// TODO por cima disto cifrar com a pubica do atm e no lado do atm fazer o mesmo
				byte[] signature = RSAKeyUtils.signData(ecdhPubKeyEncoded, keyPair.getPrivate());

				// Send the ECDH public key and its RSA signature.
				connection.send(ecdhPubKeyEncoded);
				connection.send(signature);
				System.out.println("Sent ECDH public key and RSA signature.");

				// Receive the client's ECDH public key and RSA signature.
				byte[] clientEcdhPubKeyEncoded = connection.receive(); // (byte[]) ois.readObject();
				byte[] clientSignature = connection.receive(); // (byte[]) ois.readObject();
				System.out.println("Received client's ECDH public key and RSA signature.");

				// Verify the client's signature using the client's RSA public key.
				if (!RSAKeyUtils.verifySignature(clientEcdhPubKeyEncoded, clientSignature, atmPublicKey)) {
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
				sharedSecret = keyAgree.generateSecret();
			} catch (Exception e) {
				e.printStackTrace();
			}

			System.out.println("Server computed shared secret: " + Arrays.toString(sharedSecret));
		}

		private void getClientPublicKey() {
			byte[] clientMessage = connection.receive();
			byte[] atmPublicKeyBytes;
			PublicKey atmPublicKey = null;
			try {
				atmPublicKeyBytes = RSAKeyUtils.decryptData(clientMessage, keyPair.getPrivate());
				atmPublicKey = RSAKeyUtils.convertToPublicKey(atmPublicKeyBytes);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			this.atmPublicKey = atmPublicKey;
		}

		private MessageWithSequenceNumber decryptMessage(byte[] bytes, ECDHAESEncryption ECDHKey) {
			MessageWithSequenceNumber msg = null;
			try {
				byte[] decryptedBytes = ECDHKey.decrypt(bytes);
				msg = MessageWithSequenceNumber.fromByteArray(decryptedBytes);
			} catch (Exception e) {
				e.printStackTrace();
			}
			return msg;
		}

		// Implements the handshake protocol.
		private boolean performHandshake() throws Exception {
			// Step 1: Receive the client’s public key.
			/*
			 * byte[] clientMessage = connection.receive();
			 * byte[] atmPublicKeyBytes =
			 * RSAKeyUtils.decryptData(clientMessage,keyPair.getPrivate());
			 * PublicKey atmPublicKey = RSAKeyUtils.convertToPublicKey(atmPublicKeyBytes);
			 * this.atmPublicKey = atmPublicKey;
			 */

			// Diffie–Hellman–Merkle key exchange
			// Generate an ephemeral ECDH key pair using the named curve "prime256v1".
			/*
			 * ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
			 * KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH",
			 * "BC");
			 * keyPairGenerator.initialize(ecSpec);
			 * KeyPair ecdhKeyPair = keyPairGenerator.generateKeyPair();
			 * // Get the encoded form of the ECDH public key.
			 * byte[] ecdhPubKeyEncoded = ecdhKeyPair.getPublic().getEncoded();
			 *
			 * // Sign the ECDH public key using the server's RSA private key.
			 * // TODO por cima disto cifrar com a pubica do atm e no lado do atm fazer o
			 * mesmo
			 * byte[] signature = RSAKeyUtils.signData(ecdhPubKeyEncoded,
			 * keyPair.getPrivate());
			 *
			 * // Send the ECDH public key and its RSA signature.
			 * connection.send(ecdhPubKeyEncoded);
			 * connection.send(signature);
			 * System.out.println("Sent ECDH public key and RSA signature.");
			 *
			 * // Receive the client's ECDH public key and RSA signature.
			 * byte[] clientEcdhPubKeyEncoded = connection.receive(); // (byte[])
			 * ois.readObject();
			 * byte[] clientSignature = connection.receive(); // (byte[]) ois.readObject();
			 * System.out.println("Received client's ECDH public key and RSA signature.");
			 *
			 * // Verify the client's signature using the client's RSA public key.
			 * if (!RSAKeyUtils.verifySignature(clientEcdhPubKeyEncoded, clientSignature,
			 * atmPublicKey)) {
			 * throw new SecurityException("Client's RSA signature verification failed!");
			 * }
			 * System.out.println("Client's RSA signature verified.");
			 *
			 * // Reconstruct the client's ECDH public key.
			 * KeyFactory keyFactory = KeyFactory.getInstance("ECDH", "BC");
			 * X509EncodedKeySpec keySpec = new X509EncodedKeySpec(clientEcdhPubKeyEncoded);
			 * PublicKey clientEcdhPubKey = keyFactory.generatePublic(keySpec);
			 *
			 * // Perform the ECDH key agreement.
			 * KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH", "BC");
			 * keyAgree.init(ecdhKeyPair.getPrivate());
			 * keyAgree.doPhase(clientEcdhPubKey, true);
			 * sharedSecret = keyAgree.generateSecret();
			 *
			 * System.out.println("Server computed shared secret: " +
			 * Arrays.toString(sharedSecret));
			 */
			return true;
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

	private void cleanExit() {
		//printUsage(debug);
		if (serverSocket != null && !serverSocket.isClosed()) {
			try {
				serverSocket.close();
				File file = new File(DEFAULT_AUTH_FILE);
				if (file.exists()) {
					file.delete();
				}
				// TIRARARRR
				File file2 = new File("card.file");
				if (file2.exists()) {
					file2.delete();
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	private void closeClientSocket(Socket socket) {

		if (serverSocket != null && !serverSocket.isClosed() && socket != null && !socket.isClosed()) {
			try {
				socket.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	private String extractArg(String option, int i, String[] args) {
		if (args[i].equals(option) && i + 1 >= args.length) { // -s <auth-file>
			//printUsage(debug);
			cleanExit();
		}
		return args[i].equals(option) ? args[i + 1] : option.substring(2);
	}

	private void printUsage(boolean verbose) {
		System.out.println("Usage: BankServer [-s <auth-file>] [-p <port>]");
	}

	private class ServerConfig {
		public String authFile;
		public int port;

		ServerConfig(String authFile, int port) {
			this.authFile = authFile;
			this.port = port;
		}
	}

	private void addShutdownHook() {
		Runtime.getRuntime().addShutdownHook(new Thread(() -> {
			cleanExit();
			System.out.println(EXIT_FAILURE);
		}));
	}
}
import java.io.*;
import java.net.InetSocketAddress;
import java.security.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;

//TODO verificar se ficheiro fornecido pelo input do user ja existe. se sim sair

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
	private static final int EXIT_SUCCESS = 0;

	// Attributes
	private ServerConfig config;
	private ServerSocket serverSocket;
	private final SecureRandom random = new SecureRandom();
	private int sequenceNumber = genSeq();
	private HashMap<String, Account> accounts;

	public static void main(String[] args) throws IOException {
		new BankServer(args);
	}

	public BankServer(String[] args) {
		if (!isValidArgs(args)) {
			System.out.println("255");
			cleanExit();
		}

		config = getConfigFromArgs(args);
		// criar set de contas
		accounts = new HashMap<>();

		Security.addProvider(new BouncyCastleProvider());
		try {
			KeyPair rsaKeyPair = RSAKeyUtils.generateRSAKeyPair();
			FileUtils.savePublicKey(rsaKeyPair.getPublic(), config.authFile);
			// System.out.println("chave publica banco: " +
			// rsaKeyPair.getPublic().toString());
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
			e.printStackTrace();
		}
	}

	/**
	 * This function returns true if all of its arguments are valid or false if any
	 * aren't
	 *
	 * @param args args from atm start
	 */
	private boolean isValidArgs(String[] args) {
		if (args.length > 4) {
			printUsage(debug);
			return false;
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
				printUsage(debug);
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

		// TODO descomentar e por a dar certo
		// addShutdownHook();

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
		// private SecureSocket secureSocket;
		private Connection connection;
		private PublicKey atmPublicKey;
		private byte[] sharedSecret;

		public ConnectionHandler(Socket socket, KeyPair keyPair) {
			this.socket = socket;
			this.keyPair = keyPair;
		}

		/**
		 * This is called after validation
		 */
		public void run() {
			// to be in scope of the finally block
			String json = null;

			try {
				connection = new Connection(socket);
				// secureSocket = new SecureSocket(socket, keyPair);
				if (performHandshake()) {
					System.out.println("Mutual authentication successful with " + socket.getInetAddress());
					// Further processing (e.g., transaction handling) would follow here
					ECDHAESEncryption ECDHKey = new ECDHAESEncryption(sharedSecret);

					// Send Sequential Number
					byte[] EncryptedMessageSend = ECDHKey
							.encrypt(ByteBuffer.allocate(4).putInt(sequenceNumber).array());
					System.out.println(sequenceNumber);
					// secureSocket.sendMessage(EncryptedMessageSend);
					connection.send(EncryptedMessageSend);
					// Receive Client Arguments With the right Sequential Number
					// byte[] EncryptedMessageReceive = secureSocket.receiveMessage();
					byte[] bytes = connection.receive();

					MessageWithSequenceNumber msgWithSeq = decryptMessage(bytes, ECDHKey);
					if ((msgWithSeq.sequenceNumber) != (sequenceNumber + 1)) {
						Reply reply = new Reply(Status.NOT_OK);
						connection.send(reply.toByteArray());
					} else {
						if (msgWithSeq.message.operation.op == Operations.NEW_ACCOUNT) {
							if (msgWithSeq.message.operation.balance < 10.0) {
								Reply reply = new Reply(Status.NOT_OK);
								connection.send(reply.toByteArray());
							}
							accounts.put(msgWithSeq.message.account.name,
									new Account(msgWithSeq.message.account.name,
											msgWithSeq.message.account.PIN,
											msgWithSeq.message.operation.balance));
							connection.send(new Reply(Status.OK).toByteArray());
						}
					}
					/*
					 * String ClientArguments = new
					 * String(ECDHKey.decrypt(EncryptedMessageReceive));
					 * String[] ClientArgs = ClientArguments.split(" ");
					 */

					/*
					 * for (String word : ClientArgs){
					 * System.out.println(word);
					 * }
					 */

					// Validate Sequence Number for Replay attacks
					/*
					 * if (ClientArgs[ClientArgs.length - 1].equals(String.valueOf(SequenceNumber)))
					 * {
					 * SequenceNumber++;
					 *
					 * // Arguments Processing
					 * Account currentAccount = null;
					 * boolean createAccFlag = false;
					 *
					 * // -a is required, and we need it to check if we already have that account
					 * // created
					 * for (int i = 0; i < ClientArgs.length - 1; i = i + 2) {
					 * if (ClientArgs[i].equals("-a")) {
					 * // if it exists just update the current account
					 * if (accounts.containsKey(ClientArgs[i + 1])) {
					 * currentAccount = accounts.get(ClientArgs[i + 1]);
					 * // if it doesn't exist
					 * } else {
					 * currentAccount = new Account(ClientArgs[i + 1]);
					 * accounts.put(ClientArgs[i + 1], currentAccount);
					 * createAccFlag = true;
					 * }
					 * }
					 * }
					 *
					 * for (int i = 0; i < ClientArgs.length - 1; i = i + 2) {
					 * if (ClientArgs[i + 1] != null && currentAccount != null) {
					 * switch (ClientArgs[i]) {
					 * // Optional parameters
					 * case "-c":
					 * // se foi criada anteriormente eh necessario dar set ao card file
					 * if (createAccFlag) {
					 * currentAccount.setCardFile(ClientArgs[i + 1]);
					 * }
					 * break;
					 *
					 * // Modes of Operation
					 * case "-n":
					 * if (createAccFlag) {
					 * currentAccount.setBalance(Double.parseDouble(ClientArgs[i + 1]));
					 * } else {
					 * // should execute, it means the account already exists
					 * }
					 * json = currentAccount.toJson(ClientArgs[i],
					 * Double.parseDouble(ClientArgs[i + 1]));
					 * break;
					 * case "-d":
					 * currentAccount.addBalance(Double.parseDouble(ClientArgs[i + 1]));
					 * json = currentAccount.toJson(ClientArgs[i],
					 * Double.parseDouble(ClientArgs[i + 1]));
					 * break;
					 * case "-w":
					 * currentAccount.subBalance(Double.parseDouble(ClientArgs[i + 1]));
					 * json = currentAccount.toJson(ClientArgs[i],
					 * Double.parseDouble(ClientArgs[i + 1]));
					 * break;
					 * case "-g":
					 * // TIRAR
					 * if (createAccFlag) {
					 * // should no execute, account was created now
					 * }
					 * json = currentAccount.toJson(ClientArgs[i], currentAccount.getBalance());
					 * break;
					 * }
					 * } else
					 * System.out.println("Account is null or Args malformed");
					 * // print the operation
					 * // json = currentAccount.toJson(ClientArgs[i]);
					 * }
					 *
					 * }
					 */
				} else {
					System.out.println("Mutual authentication failed with " + socket.getInetAddress());
				}
			} catch (Exception e) {
				System.out.println("Error during handshake: " + e.getMessage());
			} finally {

				// fechar socket cliente
				try {
					// secureSocket.sendMessage(json);
					connection.send(json.getBytes());
					socket.close();

				} catch (Exception e) {
					e.printStackTrace();
				}
				// cleanExit();
			}
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
			byte[] clientMessage = connection.receive();// secureSocket.receiveMessage();
			byte[] atmPublicKeyBytes = RSAKeyUtils.decryptData(clientMessage,
					/* secureSocket.getKeyPair() */keyPair.getPrivate()/* secureSocket.keyPair.getPrivate() */);
			PublicKey atmPublicKey = RSAKeyUtils.convertToPublicKey(atmPublicKeyBytes);
			this.atmPublicKey = atmPublicKey;

			// Diffie–Hellman–Merkle key exchange

			// Generate an ephemeral ECDH key pair using the named curve "prime256v1".
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
			// secureSocket.sendMessage(ecdhPubKeyEncoded);
			// secureSocket.sendMessage(signature);
			connection.send(ecdhPubKeyEncoded);
			connection.send(signature);
			System.out.println("Sent ECDH public key and RSA signature.");

			// Receive the client's ECDH public key and RSA signature.
			// byte[] clientEcdhPubKeyEncoded = secureSocket.receiveMessage(); // (byte[])
			// ois.readObject();
			// byte[] clientSignature = secureSocket.receiveMessage(); // (byte[])
			// ois.readObject();
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

			System.out.println("Server computed shared secret: " + Arrays.toString(sharedSecret));
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
		printUsage(debug);
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
		System.exit(EXIT_FAILURE);
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
			printUsage(debug);
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

	/*
	 * private void addShutdownHook() {
	 * ServerShutdown shutdownThread = new ServerShutdown();
	 * Runtime.getRuntime().addShutdownHook(shutdownThread);
	 * }
	 *
	 * class ServerShutdown extends Thread {
	 * public void run() {
	 * cleanExit();
	 * }
	 * }
	 */
}

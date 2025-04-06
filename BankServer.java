import java.io.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
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
	private static final int EXIT_SUCCESS = 0;
	private static int ERROR = EXIT_SUCCESS;
	private static ExecutorService threadPool = Executors.newCachedThreadPool();

	// Attributes
	private ServerConfig config;
	private ServerSocket serverSocket;
	private KeyPair rsaKeyPair;
	private AtomicInteger sequenceNumber = genSeq();
	private ConcurrentHashMap<String, Account> accounts = new ConcurrentHashMap<>();

	public static void main(String[] args) throws IOException {
		new BankServer(args);
	}

	public BankServer(String[] args) {

		addShutdownHook();

		Security.addProvider(new BouncyCastleProvider());
		if (!isValidArgs(args)) {
			System.exit(ERROR = EXIT_FAILURE);
		}

		config = getConfigFromArgs(args);

		rsaKeyPair = createAuthFileAndKeyPair();
		System.out.println("created");

		lauchServerSocketAndThreads();
	}

	private void lauchServerSocketAndThreads() {
		try {
			// eh siupsoto aceitarmos apenas de um porto??
			serverSocket = new ServerSocket(config.port);
			//System.out.println("Bank server listening on port " + config.port);
			// Continuously accept client connections
			// Socket clientSocket = serverSocket.accept();

			while (!serverSocket.isClosed()) {
				Socket clientSocket = serverSocket.accept();
				String clientIP = clientSocket.getInetAddress().getHostAddress();
				if (TrafficMonitor.isSuspicious(clientIP)) {
					System.out.println("IP " + clientIP +" made a big amount of requests, blocking...");
					clientSocket.close(); 
				} else {
					threadPool.submit(new ConnectionHandler(clientSocket, rsaKeyPair));
				}
			}

		} catch (Exception e) {
			System.exit(ERROR);
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

	public AtomicInteger genSeq() {
		SecureRandom random = new SecureRandom();
		return new AtomicInteger(random.nextInt(100000, 999999));
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

			try {
				connection = new Connection(socket);
				// secureSocket = new SecureSocket(socket, keyPair);
				getClientPublicKey();
				syncSessionKeys();
				if (sharedSecret != null) {
					//System.out.println("Mutual authentication successful with " + socket.getInetAddress());
					// Further processing (e.g., transaction handling) would follow here
					ECDHAESEncryption ECDHKey = getAESKeyFromSharesSecret();
					// Send Sequential Number
					int LocalSequenceNumber = sequenceNumber.get();
					sendSequenctialNumber(ECDHKey, LocalSequenceNumber);

					//socket.setSoTimeout(10000);
					//System.out.println("Setted timeout");

					MessageWithSequenceNumber msgWithSeq = receiveMessage(ECDHKey);

					try {
						processRequest(msgWithSeq, LocalSequenceNumber);
					} catch (IOException e) {
						//System.exit(ERROR = EXIT_FAILURE);
					}

				}
			} finally {
				// fechar socket cliente
				try {
					// secureSocket.sendMessage(json);
					//connection.send(json.getBytes());
					socket.close();

				} catch (Exception e) {
					//e.printStackTrace();
				}
			}
		}

		private void processRequest(MessageWithSequenceNumber msgWithSeq, int LocalSequenceNumber) throws IOException {
			Account currentAccount = null;
			if (msgWithSeq != null && msgWithSeq.getMessage().getOperation() != null && msgWithSeq.getMessage().getOperation().getOp() != null && msgWithSeq.getSequenceNumber() == (LocalSequenceNumber + 1)) {
				sequenceNumber.incrementAndGet();
				Message m = msgWithSeq.getMessage();
				Operations op = m.getOperation().getOp();
				boolean exists = false;
				String outputReply = null;

				// Verifica se já existe a conta
				if (accounts.containsKey(m.getAccount().name)) {
					currentAccount = accounts.get(m.getAccount().name);
					exists = true;
				} else {
					currentAccount = new Account(m.getAccount().name);
					//accounts.put(m.account.name, currentAccount);
				}
				switch (op) {
					case NEW_ACCOUNT:
						//caso ja exista a conta nao se pode criar novamente
						if (m.getOperation().getBalance() < 10.0 || exists) {
							Reply reply = new Reply(Status.NOT_OK, String.valueOf(EXIT_FAILURE));
							connection.send(reply.toByteArray());
							return;
						} else {
							currentAccount.setBalance(m.getOperation().getBalance());
							currentAccount.setPin(m.getAccount().PIN);
							//so queremos que ele coloque a conta no accounts caso seja uma operacao de new account
							if (exists) {
								accounts.replace(m.getAccount().name, currentAccount);
							} else { accounts.put(m.getAccount().name, currentAccount); }
							outputReply = currentAccount.toJson(m.getOperation().getOp(), currentAccount.getBalance());
							connection.send(new Reply(Status.OK, outputReply).toByteArray());
						}
						break;

					case WITHDRAW:
						if (currentAccount.getBalance() == 0.0 || !Arrays.equals(m.getAccount().PIN, currentAccount.getPin()) || m.getOperation().getBalance() > currentAccount.getBalance()) {
							Reply reply = new Reply(Status.NOT_OK, String.valueOf(EXIT_FAILURE));
							connection.send(reply.toByteArray());
							return;

						} else {
							currentAccount.subBalance(m.getOperation().getBalance());
							accounts.replace(m.getAccount().name, currentAccount);
							outputReply = currentAccount.toJson(m.getOperation().getOp(), m.getOperation().getBalance());
							connection.send(new Reply(Status.OK, outputReply).toByteArray());
						}
						break;

					case DEPOSIT:
						if (!Arrays.equals(m.getAccount().PIN, currentAccount.getPin())) {
							Reply reply = new Reply(Status.NOT_OK, String.valueOf(EXIT_FAILURE));
								connection.send(reply.toByteArray());
								return;
						} else {
							currentAccount.addBalance(m.getOperation().getBalance());
							accounts.replace(m.getAccount().name, currentAccount);
							outputReply = currentAccount.toJson(m.getOperation().getOp(), m.getOperation().getBalance());
							connection.send(new Reply(Status.OK, outputReply).toByteArray());
						}
						break;

					case GET:
						if (!Arrays.equals(m.getAccount().PIN, currentAccount.getPin())) {
							Reply reply = new Reply(Status.NOT_OK, String.valueOf(EXIT_FAILURE));
							connection.send(reply.toByteArray());
							return;
						} else {
							outputReply = currentAccount.toJson(m.getOperation().getOp(),currentAccount.getBalance());
							connection.send(new Reply(Status.OK, outputReply).toByteArray());
						}
						break;

					default:
						Reply unknownReply = new Reply(Status.NOT_OK, String.valueOf(EXIT_FAILURE));
						connection.send(unknownReply.toByteArray());
						return;
				}
			} else {
				Reply reply = new Reply(Status.NOT_OK, String.valueOf(EXIT_FAILURE));
				try {
					connection.send(reply.toByteArray());
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}



		private MessageWithSequenceNumber receiveMessage(ECDHAESEncryption ECDHKey) {
			byte[] bytes = connection.receive();
			return decryptMessage(bytes, ECDHKey);
		}

		private void sendSequenctialNumber(ECDHAESEncryption ECDHKey, int seqNum) {
			byte[] EncryptedMessageSend = null;
			try {
				EncryptedMessageSend = ECDHKey.encrypt(ByteBuffer.allocate(4).putInt(seqNum).array());
			} catch (Exception e) {
				e.printStackTrace();
			}
			//System.out.println(sequenceNumber);
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
				//System.out.println("Sent ECDH public key and RSA signature.");

				// Receive the client's ECDH public key and RSA signature.
				byte[] clientEcdhPubKeyEncoded = connection.receive(); // (byte[]) ois.readObject();
				byte[] clientSignature = connection.receive(); // (byte[]) ois.readObject();
				//System.out.println("Received client's ECDH public key and RSA signature.");

				// Verify the client's signature using the client's RSA public key.
				if (!RSAKeyUtils.verifySignature(clientEcdhPubKeyEncoded, clientSignature, atmPublicKey)) {
					throw new SecurityException("Client's RSA signature verification failed!");
				}
				//System.out.println("Client's RSA signature verified.");

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

			//System.out.println("Server computed shared secret: " + Arrays.toString(sharedSecret));
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
		if (serverSocket != null && !serverSocket.isClosed()) {
			try {
				serverSocket.close();
				//File file = new File(DEFAULT_AUTH_FILE);
				File rootDir = new File(".");
				File[] files = rootDir.listFiles();
				//System.out.println(Arrays.toString(files));
				if (files != null) {
					for (File file : files) {
						//CUIDADO AQUI
						if (file.isFile() && (file.getName().endsWith(".card") || file.getName().endsWith(".auth"))) {
							file.delete();
						}
					}
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	private String extractArg(String option, int i, String[] args) {
		if (args[i].equals(option) && i + 1 >= args.length) { return null;
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
			System.out.println(ERROR);
		}));
	}
}

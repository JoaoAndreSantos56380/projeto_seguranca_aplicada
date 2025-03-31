import java.io.*;
import java.security.*;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import java.net.ServerSocket;
import java.net.Socket;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.KeyAgreement;

//TODO verificar se ficheiro fornecido pelo input do user ja existe. se sim sair

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class BankServer {
	private static final boolean debug = false;
	private static final int PORT = 3000;
	private static final int EXIT_FAILURE = 255;
	private static final String AUTH_FILE = "bank.auth";
	private static final String ARGS_PORT = "-p";
	private static final String ARGS_AUTH_FILE = "-s";
	private static ServerSocket serverSocket;
	private static final SecureRandom random = new SecureRandom();
	private static int SequenceNumber = genSeq();

	private static Account[] accounts;

	public static void main(String[] args) throws IOException {
		if (!validateArgs(args)) {
			System.out.println("255");
			cleanExit();
			return;
		} else {

			Security.addProvider(new BouncyCastleProvider());
			int port = PORT;
			String auth_file = AUTH_FILE;
			try {
				//tratar argumentos da consola
				if (args.length > 4) {
					cleanExit();
				} else if (args.length != 0) {
					if (args[0].trim().equals(ARGS_PORT) && args[2].trim().equals(ARGS_AUTH_FILE)) {
						port = Integer.parseInt(args[1]);
						auth_file = args[3].trim();
					} else if (args[2].trim().equals(ARGS_PORT) && args[0].trim().equals(ARGS_AUTH_FILE)) {
						port = Integer.parseInt(args[3]);
						auth_file = args[1].trim();
					}
				}

				KeyPair rsaKeyPair = RSAKeyUtils.generateRSAKeyPair();
				FileUtils.savePublicKey(rsaKeyPair.getPublic(), auth_file);
				//System.out.println("chave publica banco: " + rsaKeyPair.getPublic().toString());
				serverSocket = new ServerSocket(port);
				System.out.println("Bank server listening on port " + port);

				// Continuously accept client connections
				while (true) {
					Socket clientSocket = serverSocket.accept();
					System.out.println("Accepted connection from " + clientSocket.getInetAddress());
					new Thread(new ConnectionHandler(clientSocket, rsaKeyPair)).start();
				}

			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	public static int genSeq() {
		SecureRandom random = new SecureRandom();
		//byte[] nonce = new byte[8];
		//random.nextBytes(nonce);
		return random.nextInt(100000, 999999);
	}

	// Handles a client connection and performs the handshake.
	private static class ConnectionHandler implements Runnable {
		private Socket socket;
		private KeyPair keyPair;
		private SecureSocket secureSocket;
		private PublicKey atmPublicKey;
		private byte[] sharedSecret;

		public ConnectionHandler(Socket socket, KeyPair keyPair) {
			this.socket = socket;
			this.keyPair = keyPair;
		}

		public void run() {
			try {
				
				secureSocket = new SecureSocket(socket, keyPair);
				if (performHandshake()) {	
					System.out.println("Mutual authentication successful with " + socket.getInetAddress());
					// Further processing (e.g., transaction handling) would follow here
					ECDHAESEncryption ECDHKey = new ECDHAESEncryption(sharedSecret);

					// Send Sequential Number
					byte[] EncryptedMessageSend = ECDHKey.encrypt(String.valueOf(SequenceNumber));
					secureSocket.sendMessage(EncryptedMessageSend);	

					// Receive Client Arguments With the right Sequential Number
					byte[] EncryptedMessageReceive = secureSocket.receiveMessage();
					String ClientArguments = ECDHKey.decrypt(EncryptedMessageReceive);
					String[] ClientArgs = ClientArguments.split(" ");


					for (String word : ClientArgs){
						System.out.println(word);
					}

					
					// Validate Sequence Number for Replay attacks
					if (ClientArgs[ClientArgs.length - 1].equals(String.valueOf(SequenceNumber))){
						SequenceNumber++;

						// Arguments Processing
						Account Account = new Account();
						boolean createAccount = false, deposit = false, withdraw = false, get = false;
						int CounterOperations=0;

						//nao deveriamos ter protecao contra duplicacao de comandos?
						for (int i = 0; i < ClientArgs.length-1; i=i+2){
							switch (ClientArgs[i]){
								//Optional parameters
								case "-c":
									Account.setCardFile(ClientArgs[i+1]);
								break;
								case "-a":
									Account.setName(ClientArgs[i+1]);
								break;

								//Modes of Operation
								case "-n":
									createAccount = true;
									Account.setBalance(Double.parseDouble(ClientArgs[i+1]));
									CounterOperations++;
								break;
								case "-d":
									deposit = true;
									Account.addBalance(Double.parseDouble(ClientArgs[i+1]));
									CounterOperations++;
								break;
								case "-w":
									withdraw = true;
									Account.subBalance(Double.parseDouble(ClientArgs[i+1]));
									CounterOperations++;
								break;
								case "-g":
									get = true;
								break;
							}
							if (CounterOperations==1){
								
							}
						}				
					}
				} else {
					System.out.println("Mutual authentication failed with " + socket.getInetAddress());
				}
			} catch (Exception e) {
				System.out.println("Error during handshake: " + e.getMessage());
			} finally {
				try {
					cleanExit();
				} catch (IOException e) {
				}
			}
		}

		// Implements the handshake protocol.
		private boolean performHandshake() throws Exception {
			// Step 1: Receive the client’s public key.
			byte[] clientMessage = secureSocket.receiveMessage();
			byte[] atmPublicKeyBytes = RSAKeyUtils.decryptData(clientMessage, secureSocket.getKeyPair().getPrivate()/* secureSocket.keyPair.getPrivate() */);
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
			byte[] signature = RSAKeyUtils.signData(ecdhPubKeyEncoded, keyPair.getPrivate());

			// Send the ECDH public key and its RSA signature.
			secureSocket.sendMessage(ecdhPubKeyEncoded);
			secureSocket.sendMessage(signature);
			secureSocket.flush();
			System.out.println("Sent ECDH public key and RSA signature.");

			// Receive the client's ECDH public key and RSA signature.
			byte[] clientEcdhPubKeyEncoded = secureSocket.receiveMessage(); // (byte[]) ois.readObject();
			byte[] clientSignature = secureSocket.receiveMessage(); //(byte[]) ois.readObject();
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

	/**
	 * This function returns true if all of its arguments are valid or false if any aren't
	 *
	 * @param args args from atm start
	 */
	//REVER ISTO
	private static boolean validateArgs(String[] args) throws IOException {

		if (args.length > 4) {
			printUsage(debug);
			cleanExit();
			return false;
		}

		// Set to track duplicate arguments
		Set<String> usedArgs = new HashSet<>();

		for (int i = 0; i < args.length; i += 2) {

			if (usedArgs.contains(args[i])) {
				System.out.println("Error: Duplicate argument " + args[i]);
				cleanExit();
				return false;
			}

			if (args[i].startsWith("-s")) {
				String authFilePath = extractArg("-s", i, args);
				if (!fileValidation(authFilePath)) {
					cleanExit();
					return false;
				} else usedArgs.add(args[i]);
			} else if (args[i].startsWith("-p")) {
				String port = extractArg("-p", i, args);
				if (!portValidation(port)) {
					cleanExit();
					return false;
				} else usedArgs.add(args[i]);
			} else{ // Invalid argument
					printUsage(debug);
					cleanExit();
				}
			}

		return true;
	}

	/**
	 * Validates a port if it is between 1024 and 65535
	 *
	 * @param input port to be verified
	 * @return true if it is a valid port, false otherwise
	 */
	private static boolean portValidation(String input) throws IOException {
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

	private static void cleanExit() throws IOException {
		printUsage(debug);
		//nao eh necessario mas eh uma boa pratica
		if (!serverSocket.isClosed()) {
			serverSocket.close();
		}
		System.exit(EXIT_FAILURE);
	}

	private static boolean fileValidation(String filename) throws IOException {
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

	private static String extractArg(String option, int i, String[] args) throws IOException {
		if (args[i].equals(option) && i + 1 >= args.length) { // -s <auth-file>
			printUsage(debug);
			cleanExit();
		}
		return args[i].equals(option) ? args[i + 1] : option.substring(2);
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
}
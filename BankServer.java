import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;

public class BankServer {
	private static final int PORT = 3000;
	private static final String AUTH_FILE = "bank.auth";
	private static final String ARGS_PORT = "-p";
	private static final String ARGS_AUTH_FILE = "-s";

	public static void main(String[] args) {
		int port = PORT;
		String auth_file = AUTH_FILE;
		try {
			//tratar argumentos da consola
			if(args.length > 4){
				System.out.println("255");
				return;
			}

			if(args[0].trim().equals(ARGS_PORT) && args[2].trim().equals(ARGS_AUTH_FILE)){
				port = Integer.parseInt(args[1]);
				auth_file = args[3].trim();
			} else if(args[2].trim().equals(ARGS_PORT) && args[0].trim().equals(ARGS_AUTH_FILE)){
				port = Integer.parseInt(args[3]);
				auth_file = args[1].trim();
			}

			// Load the shared secret key from the auth file
			//SecretKeySpec key = loadKey(AUTH_FILE);
			SecretKey key = generateKey(auth_file);
			saveKeyOnFile(auth_file, key);
			ServerSocket serverSocket = new ServerSocket(port);
			System.out.println("Bank server listening on port " + port);

			// Continuously accept client connections
			while (true) {
				Socket clientSocket = serverSocket.accept();
				System.out.println("Accepted connection from " + clientSocket.getInetAddress());
				new Thread(new ConnectionHandler(clientSocket, key)).start();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	// Reads a Base64-encoded key from the auth file.
	private static SecretKeySpec loadKey(String authFilePath) throws Exception {
		String keyString = new String(Files.readAllBytes(Paths.get(authFilePath))).trim();
		byte[] keyBytes = Base64.getDecoder().decode(keyString);
		return new SecretKeySpec(keyBytes, "AES");
	}

	private static SecretKey generateKey(String authFilePath) throws Exception {
		//generate random AES key
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256);
		SecretKey secretKey = keyGen.generateKey();
		return secretKey;
	}

	private static void saveKeyOnFile(String filename, SecretKey key){
		// save key in auth file
		try {
			File authFile = new File(filename);
			if (authFile.createNewFile()) {
				byte[] keyBytes = key.getEncoded();
        		String encodedKey = Base64.getEncoder().encodeToString(keyBytes);
        		try (FileWriter writer = new FileWriter(filename)) {
            		writer.write(encodedKey);
        		}
				System.out.println("created");
			} else {
				System.out.println("255");
			}
		} catch (IOException e) {
			System.out.println("Error saving file.");
			//e.printStackTrace();
		}
	}



	// Handles a client connection and performs the handshake.
	private static class ConnectionHandler implements Runnable {
		private Socket socket;
		private SecretKey key;
		private SecureSocket secureSocket;

		public ConnectionHandler(Socket socket, SecretKey key) {
			this.socket = socket;
			this.key = key;
		}

		public void run() {
			try {
				secureSocket = new SecureSocket(socket, key);
				if (performHandshake()) {
					System.out.println("Mutual authentication successful with " + socket.getInetAddress());
					// Further processing (e.g., transaction handling) would follow here.
				} else {
					System.out.println("Mutual authentication failed with " + socket.getInetAddress());
				}
			} catch (Exception e) {
				System.out.println("Error during handshake: " + e.getMessage());
			} finally {
				try {
					socket.close();
				} catch (IOException e) {
				}
			}
		}

		// Implements the handshake protocol.
		private boolean performHandshake() throws Exception {
			// Step 1: Receive the client’s nonce message.
			String clientMessage = secureSocket.receiveMessage();
			if (!clientMessage.equals("quem sou eu?")) {
				return false;
			}
			/* String clientNonce = clientMessage.substring("CLIENT_NONCE:".length());
			System.out.println("Received client nonce: " + clientNonce); */
			String id = "id";
			String segredo = "segredo";
			// Step 2: Generate bank nonce and send echo message.
			byte[] bankNonceBytes = new byte[16];
			new SecureRandom().nextBytes(bankNonceBytes);
			String bankNonce = Base64.getEncoder().encodeToString(bankNonceBytes);
			String responseMessage = id + ":" + bankNonce;
			secureSocket.sendMessage(responseMessage);
			System.out.println("Sent echo with bank nonce: " + bankNonce);

			// Step 3: Receive client’s echo of the bank nonce.
			/* String finalMessage = secureSocket.receiveMessage();
			if (!finalMessage.equals("ECHO_BANK_NONCE:" + bankNonce)) {
				return false;
			}
			System.out.println("Received valid echo of bank nonce.");
			return true; */
			return true;
		}
	}

	// SecureSocket helper class for encrypted and authenticated communication.
	private static class SecureSocket {
		private Socket socket;
		private DataInputStream in;
		private DataOutputStream out;
		private SecretKey key;

		public SecureSocket(Socket socket, SecretKey key) throws IOException {
			this.socket = socket;
			this.key = key;
			this.in = new DataInputStream(socket.getInputStream());
			this.out = new DataOutputStream(socket.getOutputStream());
		}

		// Encrypts, computes HMAC, and sends the message.
		public void sendMessage(String message) throws Exception {
			// Generate a random IV.
			byte[] iv = new byte[16];
			new SecureRandom().nextBytes(iv);
			IvParameterSpec ivSpec = new IvParameterSpec(iv);

			// Encrypt the message.
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
			byte[] encrypted = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

			// Compute HMAC over IV and ciphertext.
			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(key);
			mac.update(iv);
			mac.update(encrypted);
			byte[] hmac = mac.doFinal();

			// Send lengths and then the IV, ciphertext, and HMAC.
			out.writeInt(iv.length);
			out.write(iv);
			out.writeInt(encrypted.length);
			out.write(encrypted);
			out.writeInt(hmac.length);
			out.write(hmac);
			out.flush();
		}

		// Reads, verifies HMAC, and decrypts a received message.
		public String receiveMessage() throws Exception {
			int ivLength = in.readInt();
			byte[] iv = new byte[ivLength];
			in.readFully(iv);

			int encryptedLength = in.readInt();
			byte[] encrypted = new byte[encryptedLength];
			in.readFully(encrypted);

			int hmacLength = in.readInt();
			byte[] receivedHmac = new byte[hmacLength];
			in.readFully(receivedHmac);

			// Verify HMAC.
			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(key);
			mac.update(iv);
			mac.update(encrypted);
			byte[] expectedHmac = mac.doFinal();
			if (!Arrays.equals(receivedHmac, expectedHmac)) {
				throw new SecurityException("HMAC verification failed");
			}

			// Decrypt the message.
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
			byte[] decrypted = cipher.doFinal(encrypted);
			return new String(decrypted, StandardCharsets.UTF_8);
		}
	}
}

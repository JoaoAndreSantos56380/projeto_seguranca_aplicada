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

public class ATMClient {
	private static final String SERVER_IP = "127.0.0.1";
	private static final int SERVER_PORT = 3000;
	private static final String AUTH_FILE = "bank.auth"; // Shared auth file

	public static void main(String[] args) {
		try {
			// Load the shared secret key from the auth file.
			SecretKeySpec key = loadKey(AUTH_FILE);
			Socket socket = new Socket(SERVER_IP, SERVER_PORT);
			System.out.println("Connected to server at " + SERVER_IP + ":" + SERVER_PORT);

			SecureSocket secureSocket = new SecureSocket(socket, key);
			if (performHandshake(secureSocket)) {
				System.out.println("Mutual authentication successful!");
				// Further processing after authentication can follow here.
			} else {
				System.out.println("Mutual authentication failed!");
			}
			socket.close();
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

	// Implements the handshake protocol.
	private static boolean performHandshake(SecureSocket secureSocket) throws Exception {
		// Step 1: Generate a client nonce and send it.
		byte[] clientNonceBytes = new byte[16];
		new SecureRandom().nextBytes(clientNonceBytes);
		String clientNonce = Base64.getEncoder().encodeToString(clientNonceBytes);
		secureSocket.sendMessage("CLIENT_NONCE:" + clientNonce);
		System.out.println("Sent client nonce: " + clientNonce);

		// Step 2: Receive the server's response.
		String response = secureSocket.receiveMessage();
		// Expecting: "ECHO:<clientNonce>:BANK_NONCE:<bankNonce>"
		if (!response.startsWith("ECHO:" + clientNonce + ":BANK_NONCE:")) {
			System.out.println("Unexpected handshake response: " + response);
			return false;
		}
		String bankNonce = response.substring(("ECHO:" + clientNonce + ":BANK_NONCE:").length());
		System.out.println("Received bank nonce: " + bankNonce);

		// Step 3: Echo back the bank nonce.
		secureSocket.sendMessage("ECHO_BANK_NONCE:" + bankNonce);
		System.out.println("Sent echo for bank nonce.");
		return true;
	}

	// SecureSocket helper class for encrypted and authenticated communication.
	private static class SecureSocket {
		private Socket socket;
		private DataInputStream in;
		private DataOutputStream out;
		private SecretKeySpec key;

		public SecureSocket(Socket socket, SecretKeySpec key) throws IOException {
			this.socket = socket;
			this.key = key;
			this.in = new DataInputStream(socket.getInputStream());
			this.out = new DataOutputStream(socket.getOutputStream());
		}

		// Encrypts, computes HMAC, and sends the message.
		public void sendMessage(String message) throws Exception {
			byte[] iv = new byte[16];
			new SecureRandom().nextBytes(iv);
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
			byte[] encrypted = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(key);
			mac.update(iv);
			mac.update(encrypted);
			byte[] hmac = mac.doFinal();

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

			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(key);
			mac.update(iv);
			mac.update(encrypted);
			byte[] expectedHmac = mac.doFinal();
			if (!Arrays.equals(receivedHmac, expectedHmac)) {
				throw new SecurityException("HMAC verification failed");
			}

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
			byte[] decrypted = cipher.doFinal(encrypted);
			return new String(decrypted, StandardCharsets.UTF_8);
		}
	}
}

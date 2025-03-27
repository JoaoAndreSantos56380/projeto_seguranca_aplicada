import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Scanner;

public class ATMClient {
	private static final String SERVER_IP = "127.0.0.1";
	private static final int SERVER_PORT = 3000;
	private static final String AUTH_FILE = "bank.auth"; // Shared auth file

	public static void main(String[] args) {
		try {
			// Load the shared secret key from the auth file.

			SecretKey key = loadKey(AUTH_FILE);
			Socket socket = new Socket(SERVER_IP, SERVER_PORT);
			System.out.println("Connected to server at " + SERVER_IP + ":" + SERVER_PORT);

			SecureSocket secureSocket = new SecureSocket(socket, key);
			if (performHandshake(secureSocket)) {
				System.out.println("Mutual authentication successful!");
				// Further processing after authentication can follow here.
			} else {
				System.out.println("Mutual authentication failed!");
			}

			//inputValidation(args);


			socket.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	// Reads a Base64-encoded key from the auth file.
	private static SecretKey loadKey(String authFilePath) throws Exception {
		String keyString = new String(Files.readAllBytes(Paths.get(authFilePath))).trim();
		byte[] keyBytes = Base64.getDecoder().decode(keyString);
		return new SecretKeySpec(keyBytes, "AES");
	}

	// Implements the handshake protocol.
	private static boolean performHandshake(SecureSocket secureSocket) throws Exception {
		String whoami = "quem sou eu?";
		secureSocket.sendMessage(whoami);

		String id_secret = secureSocket.receiveMessage();
		return true;

		/* // Step 1: Generate a client nonce and send it.
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
		return true; */
	}

	private static void inputValidation(String[] args) {

		if (!(args == null || args.length == 0 || args.length > 4096)) {

			//THIS LOOP IS JUST TO TEST
/*
			Scanner scanner = new Scanner(System.in);
			while (true) {

				System.out.print("Enter some input: ");
				String userInput = scanner.nextLine();

				boolean value = portValidation(userInput);
				System.out.println(value);
			}*/

			//return true;
		} //else return false;

	}

	/**
	 *
	 * @param input Number part to be validated
	 * @return true if it corresponds to a number, false otherwise
	 */
	private static boolean numberValidation(String input) {
		String regex = "0|[1-9][0-9]*";

		Pattern pattern = Pattern.compile(regex);
		Matcher matcher = pattern.matcher(input);

		return matcher.matches();
	}

	/**
	 * This function is supposed to receive ONLY the FRACTIONAL part of the number
	 * example: 9487599.43 -> only the 43 passes through this function
	 *
	 * @param input fraction part of the number to be validated
	 * @return true if it corresponds to a 2 decimal place fractional number, false otherwise
	 */
	private static boolean fractionValidation (String input) {
		String regex = "[0-9]{2}";

		Pattern pattern = Pattern.compile(regex);
		Matcher matcher = pattern.matcher(input);

		return matcher.matches();
	}

	/**
	 *
	 * Does it make sense to allowa multiple "."?
	 *
	 * @param input file name to be verified
	 * @return true if it is a valid filename, false otherwise
	 */
	private static boolean fileValidation (String input) {
		if (input != null && !input.isEmpty() && input.length() <= 127) {

			String dotRegex = "^\\.$|^\\.\\.$";
			Pattern dotPattern = Pattern.compile(dotRegex);

			//if it isn't only "." ".."
			if (!dotPattern.matcher(input).matches()) {

				String regex = "^[\\-_\\.0-9a-z]+$";

				Pattern pattern = Pattern.compile(regex);
				Matcher matcher = pattern.matcher(input);

				return matcher.matches();

			}else return false;
		} else return false;
	}

	/**
	 *
	 * @param input account name to be verified
	 * @return true if it is a valid account name, false otherwise
	 */
	private static boolean accountValidation (String input) {
		if (input != null && !input.isEmpty() && input.length() <= 122) {

			String regex = "^[\\-_\\.0-9a-z]+$";

			Pattern pattern = Pattern.compile(regex);
			Matcher matcher = pattern.matcher(input);

			return matcher.matches();

		} else return false;
	}

	/**
	 *
	 * @param input ip to be verified
	 * @return true if it is a valid ip, false otherwise
	 */
	private static boolean ipValidation (String input) {
		if (input != null && !input.isEmpty() && input.length() <= 16) {

			String regex = "(\\b25[0-5]|\\b2[0-4][0-9]|\\b[01]?[0-9][0-9]?)(\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}";

			Pattern pattern = Pattern.compile(regex);
			Matcher matcher = pattern.matcher(input);

			return matcher.matches();

		} else return false;
	}

	/**
	 * Validates a port if it is between 1024 and 65535
	 *
	 * @param input port to be verified
	 * @return true if it is a valid port, false otherwise
	 */
	private static boolean portValidation (String input) {
		if (input != null && !input.isEmpty() && input.length() <= 16) {

			String regex = "^(102[4-9]|10[3-9][0-9]|1[1-9][0-9][0-9]|[2-9][0-9]{3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$";

			Pattern pattern = Pattern.compile(regex);
			Matcher matcher = pattern.matcher(input);

			return matcher.matches();
			/*
			tested with this function
			Random r = new Random();
			int temp;
			for (int i = 0; i <= 10000; i++) {
				temp = r.nextInt(1024, 65536);
				if (!portValidation(String.valueOf(temp))) {
					System.out.println("Failed for port " + temp);
				}
			}*/

		} else return false;
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
			byte[] iv = new byte[16];
			new SecureRandom().nextBytes(iv);
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
			byte[] encrypted = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));


			out.write(iv);
			out.writeInt(encrypted.length);
			out.write(encrypted);
			out.flush();
			/* Mac mac = Mac.getInstance("HmacSHA256");
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
			out.flush(); */
		}

		// Reads, verifies HMAC, and decrypts a received message.
		public String receiveMessage() throws Exception {
			int ivLength = in.readInt();
			byte[] iv = new byte[ivLength];
			in.readFully(iv);

			int encryptedLength = in.readInt();
			byte[] encrypted = new byte[encryptedLength];
			in.readFully(encrypted);

			/* int hmacLength = in.readInt();
			byte[] receivedHmac = new byte[hmacLength];
			in.readFully(receivedHmac);

			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(key);
			mac.update(iv);
			mac.update(encrypted);
			byte[] expectedHmac = mac.doFinal();
			if (!Arrays.equals(receivedHmac, expectedHmac)) {
				throw new SecurityException("HMAC verification failed");
			} */

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
			byte[] decrypted = cipher.doFinal(encrypted);
			return new String(decrypted, StandardCharsets.UTF_8);
		}
	}
}

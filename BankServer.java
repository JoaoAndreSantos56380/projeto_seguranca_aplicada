import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.*;
import javax.crypto.spec.*;

import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.Security;
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

	public static void main(String[] args) {
		validateArgs(args);
		Security.addProvider(new BouncyCastleProvider());
		int port = PORT;
		String auth_file = AUTH_FILE;
		try {
			//tratar argumentos da consola
			if(args.length > 4){
				System.out.println("255");
				return;
			}
			if (args.length != 0){
				if(args[0].trim().equals(ARGS_PORT) && args[2].trim().equals(ARGS_AUTH_FILE)){
					port = Integer.parseInt(args[1]);
					auth_file = args[3].trim();
				} else if(args[2].trim().equals(ARGS_PORT) && args[0].trim().equals(ARGS_AUTH_FILE)){
					port = Integer.parseInt(args[3]);
					auth_file = args[1].trim();
				}
			} else{

			}

			KeyPair rsaKeyPair = RSAKeyUtils.generateRSAKeyPair();
			FileUtils.savePublicKey(rsaKeyPair.getPublic(), auth_file);
			//System.out.println("chave publica banco: " + rsaKeyPair.getPublic().toString());
			ServerSocket serverSocket = new ServerSocket(port);
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

	// Handles a client connection and performs the handshake.
	private static class ConnectionHandler implements Runnable {
		private Socket socket;
		private KeyPair keyPair;
		private SecureSocket secureSocket;
		private PublicKey atmPublicKey;

		public ConnectionHandler(Socket socket, KeyPair keyPair) {
			this.socket = socket;
			this.keyPair = keyPair;
		}

		public void run() {
			try {
				secureSocket = new SecureSocket(socket, keyPair);
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
			byte[] sharedSecret = keyAgree.generateSecret();
			System.out.println("Server computed shared secret: " + Arrays.toString(sharedSecret));
			return true;
		}
	}

	private static void validateArgs(String[] args) {
		if (args.length > 4) {
			printUsage(debug);
			// TODO fazer saida suave: cleanExit()
			System.exit(EXIT_FAILURE);
		}

		for (int i = 0; i < args.length; i += 2) {
			if (args[i].startsWith("-s")) {
				String authFilePath = extractArg("-s", i, args);
				fileValidation(authFilePath);
			} else if (args[i].startsWith("-p")) {
				String port = extractArg("-p", i, args);
				portValidation(port);

			} else { // Invalid argument
				printUsage(debug);
				// TODO fazer saida suave: cleanExit()
				System.exit(EXIT_FAILURE);
			}
		}
	}

	/**
	 * Validates a port if it is between 1024 and 65535
	 *
	 * @param input port to be verified
	 * @return true if it is a valid port, false otherwise
	 */
	private static void portValidation(String input) {
		if (!canConvertStringToInt(input)) {
			cleanExit();
		}

		int port = Integer.parseInt(input);
		if (port < 1024 || port > 65535) {
			cleanExit();
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

	private static void cleanExit() {
		printUsage(debug);
		// TODO fazer saida suave: cleanExit()
		System.exit(EXIT_FAILURE);
	}

	private static boolean fileValidation(String filename) {
		if (filename == null) {
			cleanExit();
		}
		if (filename.isEmpty()) {
			cleanExit();
		}
		if (filename.length() > 127) {
			cleanExit();
		}

		// String dotRegex = "^\\.$|^\\.\\.$";
		// Pattern dotPattern = Pattern.compile(dotRegex);

		String filenameRegex = "^[\\-_\\.0-9a-z]+$";
		Pattern pattern = Pattern.compile(filenameRegex);
		Matcher matcher = pattern.matcher(filename);

		File file = new File(filename);
		if (!file.exists()) {
			System.out.print(debug ? String.format("%s: not such file\n", filename) : "");
			cleanExit();
			/*
			 * printUsage(debug);
			 * // TODO fazer saida suave: cleanExit()
			 * System.exit(EXIT_FAILURE);
			 */
		}

		return matcher.matches();
	}

	private static String extractArg(String option, int i, String[] args) {
		if (args[i].equals(option) && i + 1 >= args.length) { // -s <auth-file>
			printUsage(debug);
			// TODO fazer saida suave: cleanExit()
			System.exit(EXIT_FAILURE);
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

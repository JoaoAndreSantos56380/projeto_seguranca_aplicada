import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;
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
	private static final int PORT = 3000;
	private static final String AUTH_FILE = "bank.auth";
	private static final String ARGS_PORT = "-p";
	private static final String ARGS_AUTH_FILE = "-s";

	public static void main(String[] args) {
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

			/* ois.close();
			oos.close();
			socket.close();
			serverSocket.close(); */

			//System.out.println("public key do atm: " + atmPublicKey.toString());
			return true;
		}
	}

	/* // SecureSocket helper class for encrypted and authenticated communication.
	private static class SecureSocket {
		private Socket socket;
		private ObjectInputStream in;
		private ObjectOutputStream out;
		private KeyPair keyPair;

		public SecureSocket(Socket socket, KeyPair keyPair) throws IOException {
			this.socket = socket;
			this.keyPair = keyPair;
			this.in = new ObjectInputStream(socket.getInputStream());
			this.out = new ObjectOutputStream(socket.getOutputStream());
		}

		public void sendMessage(String message) throws Exception {
			this.out.writeObject(message);
		}

		public void sendMessage(byte[] message) throws Exception {
			this.out.writeObject(message);
		}

		// Reads, verifies HMAC, and decrypts a received message.
		public byte[] receiveMessage() throws Exception {
			return (byte[]) this.in.readObject();
		}

		public void close(){
			try {
				this.socket.close();
			} catch (IOException e) {
				//e.printStackTrace();
				System.out.println("senhora socket nao quis fechar");
			}
		}

		public void flush(){
			try {
				this.out.flush();
			} catch (IOException e) {
				//
				e.printStackTrace();
			}
		}
	} */
}

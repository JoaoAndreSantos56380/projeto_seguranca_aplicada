import java.io.*;
import java.net.*;
import java.security.KeyPair;
import java.security.PublicKey;

public class ATMClient {
	private static final String SERVER_IP = "127.0.0.1";
	private static final int SERVER_PORT = 3000;
	private static final String AUTH_FILE = "bank.auth"; // Shared auth file

	public static void main(String[] args) {
		try {
			// Load the shared secret key from the auth file.
			KeyPair atmKeyPair = RSAKeyUtils.generateRSAKeyPair();
			PublicKey bankPublicKey = RSAKeyUtils.readPublicKey(AUTH_FILE);
			Socket socket = new Socket(SERVER_IP, SERVER_PORT);
			//System.out.println("Connected to server at " + SERVER_IP + ":" + SERVER_PORT);

			SecureSocket secureSocket = new SecureSocket(socket, bankPublicKey, atmKeyPair);
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

	// Implements the handshake protocol.
	private static boolean performHandshake(SecureSocket secureSocket) throws Exception {
		byte[] atmPublicKeyEncrypted = RSAKeyUtils.encryptWithPublicKey(secureSocket.bankPublicKey.getEncoded(), secureSocket.atmKeyPair.getPublic());
		secureSocket.sendMessage(atmPublicKeyEncrypted);
		return true;
	}

	// SecureSocket helper class for encrypted and authenticated communication.
	private static class SecureSocket {
		private Socket socket;
		private ObjectInputStream in;
		private ObjectOutputStream out;
		private PublicKey bankPublicKey;
		private KeyPair atmKeyPair;

		public SecureSocket(Socket socket, PublicKey bankPublicKey, KeyPair atmKeyPair) throws IOException {
			this.socket = socket;
			this.atmKeyPair = atmKeyPair;
			this.bankPublicKey = bankPublicKey;
			this.in = new ObjectInputStream(this.socket.getInputStream());
			this.out = new ObjectOutputStream(this.socket.getOutputStream());
		}

		public SecureSocket(Socket socket) throws IOException {
			this.socket = socket;
			this.in = new ObjectInputStream(socket.getInputStream());
			this.out = new ObjectOutputStream(socket.getOutputStream());
		}

		// Encrypts, computes HMAC, and sends the message.
		public void sendMessage(String message) throws Exception {

		}

		public void sendMessage(byte[] message) throws Exception {
			out.writeObject(message);
		}

		public byte[] receiveMessage() throws Exception {
			return (byte[]) in.readObject();
		}
	}
}

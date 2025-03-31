// SecureSocket helper class for encrypted and authenticated communication.

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;

public class SecureSocket {
	private Socket socket;
	private ObjectInputStream in;
	private ObjectOutputStream out;
	private KeyPair keyPair;
	private PublicKey bankPublicKey;

	public SecureSocket(Socket socket, KeyPair keyPair) throws IOException {
		this.socket = socket;
		this.keyPair = keyPair;
		this.in = new ObjectInputStream(socket.getInputStream());
		this.out = new ObjectOutputStream(socket.getOutputStream());
	}

	public SecureSocket(Socket socket, PublicKey bankPublicKey, KeyPair atmKeyPair) throws IOException {
		this.socket = socket;
		this.bankPublicKey = bankPublicKey;
		this.keyPair = atmKeyPair;
		this.out = new ObjectOutputStream(socket.getOutputStream());
		this.in = new ObjectInputStream(socket.getInputStream());
	}

	public KeyPair getKeyPair(){
		return this.keyPair;
	}

	public Socket getSocket(){
		return this.socket;
	}

	public void sendMessage(String message) throws Exception {
		this.out.writeObject(message);
	}

	public void sendMessage(byte[] message) throws Exception {
		this.out.writeObject(message);
		this.out.flush();
	}

	// Reads, verifies HMAC, and decrypts a received message.
	public byte[] receiveMessage() throws Exception {
		return (byte[]) this.in.readObject();
	}

	public void close() {
		try {
			this.socket.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public boolean isClosed() {
        return this.socket.isClosed();
    }

	public void closeStreams() {
		try {
			this.in.close();
			this.out.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}


	public void flush() {
		try {
			this.out.flush();
		} catch (IOException e) {
			//e.printStackTrace();
			System.out.println("not flushed");
		}
	}

	public PublicKey getBankPublicKey() {
		return bankPublicKey;
	}
}

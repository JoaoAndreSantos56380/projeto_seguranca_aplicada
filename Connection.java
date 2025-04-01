import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

public class Connection {
	private Socket socket;
	private ObjectInputStream in;
	private ObjectOutputStream out;

	public Connection(Socket socket) {
		this.socket = socket;
		try {
			out = new ObjectOutputStream(socket.getOutputStream());
			in = new ObjectInputStream(socket.getInputStream());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public void send(byte[] arr) {
		try {
			out.writeObject(arr);
			out.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public byte[] receive() {
		byte[] arr = null;
		try {
			arr = (byte[]) in.readObject();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return arr;
	}

	public void close() {
		try {
			in.close();
			out.close();
			socket.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class Reply implements Serializable{
	Status status;

	double balance;

	public Reply(Status status, double balance) {
		this.status = status;
		this.balance = balance;
	}

	public Reply(Status status) {
		this.status = status;
	}

	public byte[] toByteArray() throws IOException {
		try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
				ObjectOutputStream oos = new ObjectOutputStream(bos)) {
			oos.writeObject(this);
			oos.flush();
			return bos.toByteArray();
		}
	}

	public static Object fromByteArray(byte[] data) {
		try (ByteArrayInputStream bis = new ByteArrayInputStream(data);
				ObjectInputStream ois = new ObjectInputStream(bis)) {
			return ois.readObject();
		} catch (IOException | ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	}
}

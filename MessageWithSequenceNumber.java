import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class MessageWithSequenceNumber implements Serializable {
	private Message message;
	private int sequenceNumber;

	public MessageWithSequenceNumber(Message message, int sequenceNumber) {
		this.message = message;
		this.sequenceNumber = sequenceNumber;
	}

	public Message getMessage() {
		return message;
	}
	
	public int getSequenceNumber() {
		return sequenceNumber;
	}

	public byte[] toByteArray() {
		ByteArrayOutputStream bos = null;
		try {
			bos = new ByteArrayOutputStream();
			ObjectOutputStream oos = new ObjectOutputStream(bos);
			oos.writeObject(this);
			oos.flush();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return bos.toByteArray();
	}

	public static MessageWithSequenceNumber fromByteArray(byte[] data) {
		MessageWithSequenceNumber msg = null;
		try {
			ByteArrayInputStream bis = new ByteArrayInputStream(data);
			ObjectInputStream ois = new ObjectInputStream(bis);
			msg = (MessageWithSequenceNumber) ois.readObject();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return msg;
	}
}
// nonce
// HMAC
// Encriptação

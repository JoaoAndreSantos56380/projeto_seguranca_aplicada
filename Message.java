import java.io.Serializable;

public class Message implements Serializable {
	ClientAccount account;
	Operation operation;

	public Message(ClientAccount account, Operation operation) {
		this.account = account;
		this.operation = operation;
	}
}

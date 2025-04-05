import java.io.Serializable;

public class Message implements Serializable {
	private ClientAccount account;
	private Operation operation;

	public Message(ClientAccount account, Operation operation) {
		this.account = account;
		this.operation = operation;
	}

	public Operation getOperation() {
		return operation;
	}

	public ClientAccount getAccount() {
		return account;
	}
}

import java.io.Serializable;

public class Message implements Serializable {
	private ClientAccount account;
	private Operation operation;

	public Message(ClientAccount account, Operation operation) {
		this.account = account;
		this.operation = operation;
	}

	public synchronized Operation getOperation() {
		return operation;
	}

	public synchronized ClientAccount getAccount() {
		return account;
	}
}

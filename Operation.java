import java.io.Serializable;

public class Operation implements Serializable{
	private Operations op;
	private double balance;

	public Operation(Operations op, double balance) {
		this.op = op;
		this.balance = balance;
	}

	public synchronized Operations getOp() {
		return op;
	}

	public synchronized double getBalance() {
		return balance;
	}
}

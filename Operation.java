import java.io.Serializable;

public class Operation implements Serializable{
	private Operations op;
	private double balance;

	public Operation(Operations op, double balance) {
		this.op = op;
		this.balance = balance;
	}

	public Operations getOp() {
		return op;
	}

	public double getBalance() {
		return balance;
	}
}

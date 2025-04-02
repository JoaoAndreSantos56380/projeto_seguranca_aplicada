import java.io.Serializable;

public class Operation implements Serializable{
	Operations op;
	double balance;

	public Operation(Operations op, double balance) {
		this.op = op;
		this.balance = balance;
	}
}

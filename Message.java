public class Message {
	String accountName;
	byte[] pin;
	Operations operation;

	double balance;

	// Constructor
	public Message(byte[] pin, Operations operation, double balance, String accountName) {
		this.accountName = accountName;
		this.pin = pin;
		this.operation = operation;
		this.balance = balance;
	}

	public Message(byte[] pin, Operations operation, String accountName) {
		this.accountName = accountName;
		this.pin = pin;
		this.operation = operation;
	}
}

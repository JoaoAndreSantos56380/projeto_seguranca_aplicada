public class Message {

	int sequenceNumber;
	int messageLength;
	long mac;
	String playload;

	// Constructor
	public Message(int sequenceNumber, int messageLength, long mac, String playload) {
		this.sequenceNumber = sequenceNumber;
		this.messageLength = messageLength;
		this.mac = mac;//E(mensgem em calro + mac)
		this.playload = playload;
	}

	// Getters
	public int getSequenceNumber() {
		return sequenceNumber;
	}

	public int getMessageLength() {
		return messageLength;
	}

	public long getMac() {
		return mac;
	}

	public String getPlayload() {
		return playload;
	}

	// Setters
	public void setSequenceNumber(int sequenceNumber) {
		this.sequenceNumber = sequenceNumber;
	}

	public void setMessageLength(int messageLength) {
		this.messageLength = messageLength;
	}

	public void setMac(long mac) {
		this.mac = mac;
	}

	public void setPlayload(String playload) {
		this.playload = playload;
	}

}

public class Account {
    private String name;
    private byte[] pin;
    private double balance;

    public Account() {
    }

    public Account(String name) {
        this.name = name;
    }

    public Account(String name, byte[] pin, double balance) {
        this.name = name;
        this.pin = pin;
        this.balance = balance;
    }

    public void setName (String name){
        this.name = name;
    }

    public String getName (){ return this.name; }

    public void setBalance (double value){
        this.balance = value;
    }

    public void addBalance (double value){
        this.balance += value;
    }

    public void subBalance(double value){
        this.balance -= value;
    }

    public double getBalance (){ return this.balance; }

	public byte[] getPin(){
		return this.pin;
	}

    public void setPin (byte[] pin){
        this.pin = pin;
    }

    public String toJson(Operations operation, double amount) {
        StringBuilder json = new StringBuilder("{\"account\":\"");
        json.append(name).append("\",");

        switch (operation) {
            case NEW_ACCOUNT -> json.append("\"initial_balance\":").append(amount);
            case DEPOSIT -> json.append("\"deposit\":").append(amount);
            case WITHDRAW -> json.append("\"withdraw\":").append(amount);
            case GET -> json.append("\"balance\":").append(amount);
        }
        json.append("}");
        System.out.println(json);
        return json.toString();
    }
}

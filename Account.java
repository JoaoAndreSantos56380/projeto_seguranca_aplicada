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

    public synchronized void setName(String name) {
        this.name = name;
    }

    public synchronized String getName() {
        return this.name;
    }

    public synchronized void setBalance(double value) {
        this.balance = value;
    }

    public synchronized void addBalance(double value) {
        this.balance += value;
    }

    public synchronized void subBalance(double value) {
        this.balance -= value;
    }

    public synchronized double getBalance() {
        return this.balance;
    }

    public synchronized byte[] getPin() {
        return this.pin;
    }

    public synchronized void setPin(byte[] pin) {
        this.pin = pin;
    }

    public synchronized String toJson(Operations operation, double amount) {
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

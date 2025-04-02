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

    /* public void setCardFile (String cardFile){
        this.cardFile = cardFile;
    } */

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

    /* public boolean verifyAccount() {
        return this.name != null && this.cardFile != null && this.balance != null;
    } */

    public String toJson(String operation, Double amount) {
        StringBuilder json = new StringBuilder("{\"account\":\"");
        json.append(name).append("\",");

        switch (operation) {
            case "-n" -> json.append("\"initial_balance\":").append(amount);
            case "-d" -> json.append("\"deposit\":").append(amount);
            case "-w" -> json.append("\"withdraw\":").append(amount);
            case "-g" -> json.append("\"balance\":").append(amount);
        }
        json.append("}");
        System.out.println(json);
        return json.toString();
    }
}

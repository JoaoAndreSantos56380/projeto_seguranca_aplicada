public class Account {
    private String name;
    private String cardFile;
    private Double balance;

    public Account() {
    }

    public Account(String name, String cardFile, Double balance) {
        this.name = name;
        this.cardFile = cardFile;
        this.balance = balance;
    }

    public void setName (String name){
        this.name = name;
    }

    public void setCardFile (String cardFile){
        this.cardFile = cardFile;
    }

    public void setBalance (Double value){
        this.balance = value;
    }

    public void addBalance (Double value){
        this.balance += value;
    }

    public void subBalance(Double value){
        this.balance -= value;
    }

    public double getBalance (){
        return this.balance;
    }

    public boolean verifyAccount() {
        return this.name != null && this.cardFile != null && this.balance != null;
    }

    public String toJson() {
        return "{" +
                "\"account\":\"" + name + "\"," +
                //THIS NEEDS TO BE REMOVED AFTER TESTING
                "\"cardFile\":\"" + cardFile + "\"," +
                "\"initial_balance\":" + balance +
                "}";
    }

    public String toJson(String operation, Double amount) {
        StringBuilder json = new StringBuilder("{");
        json.append("\"account\":\"").append(name).append("\",");

        if ("balance".equals(operation)) {
            json.append("\"balance\":").append(balance);
        } else if ("withdraw".equals(operation)) {
            json.append("\"withdraw\":").append(amount);
        } else if ("deposit".equals(operation)) {
            json.append("\"deposit\":").append(amount);
        } else {
            throw new IllegalArgumentException("Invalid operation: " + operation);
        }

        json.append("}");
        return json.toString();
    }
}

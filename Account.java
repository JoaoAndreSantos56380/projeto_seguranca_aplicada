public class Account {
    private String Name;
    private String cardFile;
    private Double balance;

    public void setName (String Name){
        this.Name = Name;
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
        return this.Name != null && this.cardFile != null && this.balance != null;
    }

    public String toJson() {
        return "{" +
                "\"Name\":\"" + (Name != null ? Name : "") + "\"," +
                "\"cardFile\":\"" + (cardFile != null ? cardFile : "") + "\"," +
                "\"balance\":" + (balance != null ? balance : "null") +
                "}";
    }
}

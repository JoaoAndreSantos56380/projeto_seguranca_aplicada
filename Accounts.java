public class Accounts {
    private  String Name;
    private String cardFile;
    private Double balance;

    public void setName (String Name){
        this.Name=Name;
    }

    public void setCardFile (String cardFile){
        this.cardFile=cardFile;
    }

    public void setBalance (Double balance){
        this.balance=balance;
    }

    public void addBalance (Double addition){
        this.balance += addition;
    }

    public void LessBalance (Double less){
        this.balance -= less;
    }

    public double getBalance (){
        return this.balance;
    }
    public boolean VerifyAccount() {
        if (this.Name==null || this.cardFile==null || this.balance==null)
            return false;
        else
            return true;
    }

    public String toJson() {
        return "{" +
                "\"Name\":\"" + (Name != null ? Name : "") + "\"," +
                "\"cardFile\":\"" + (cardFile != null ? cardFile : "") + "\"," +
                "\"balance\":" + (balance != null ? balance : "null") +
                "}";
    }
}

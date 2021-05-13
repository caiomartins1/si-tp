package pt.ubi.di.connection;

import pt.ubi.di.Model.Validations;

public class Aplication {
    public static void main(String[] args) {
        String ip = "127.0.0.1";
        int port = 1234;
        String name = "Name";
        System.out.println("Application Started!");
        String[] ans;
        while(true){
            ans = Validations.readString().split(" ");
            switch(ans[1]){
                case"Setup Server":
                    Server server = new Server(1234);
                    break;
                case"Setup Client":
                    Client c = new Client(ip,port,name);
                    break;
            }
        }
    }
}

package pt.ubi.di.connection;

import pt.ubi.di.Model.Validations;

public class Application {
    public static void main(String[] args) {
        String ip = "127.0.0.1";
        int port = 1234;
        String name = "Name";
        Client c = new Client(ip, port, name);
    }
}

package pt.ubi.di;

import pt.ubi.di.Model.Client;
import pt.ubi.di.Model.Server;

public class Aplication {
    public static void main(String[] args) {
        Client c = new Client();
        c.startConnection();
    }
}

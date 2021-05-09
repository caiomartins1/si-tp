package pt.ubi.di.connection;

import pt.ubi.di.Model.Client_Lite;
import pt.ubi.di.Model.Server_Lite;
import pt.ubi.di.Model.ThreadListenning;
import pt.ubi.di.Model.Validations;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.Arrays;
import java.util.stream.Stream;

public class Client {

    private final String ip;
    private final int port;
    private final String connectionName;
    private Socket socket;
    private ObjectInputStream inputStream;
    private ObjectOutputStream outputStream;
    private Client_Lite client_lite;

    public Client() {
        this.ip = "127.0.0.1";
        this.port = 1234;
        this.connectionName = "Nameless";
        try {
            socket = new Socket(ip, port);
            inputStream = new ObjectInputStream(socket.getInputStream());
            outputStream = new ObjectOutputStream(socket.getOutputStream());
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
        System.out.println("Inicio");
        new ThreadListenning(connectionName,ip,port);
        System.out.println("Saida");
        startConnection();
    }

    public Client(String ip, int port, String connectionName) {
        this.ip = ip;
        this.port = port;
        this.connectionName = connectionName;
        try {
            socket = new Socket(ip, port);
            inputStream = new ObjectInputStream(socket.getInputStream());
            outputStream = new ObjectOutputStream(socket.getOutputStream());
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
        new ThreadListenning(connectionName,ip,port);
        startConnection();
    }

    public void startConnection() {
        String[] ans;
        String[] name = {connectionName};
        try {
            while (true) {
                ans = Validations.readString().split(" ");
                String[] both = Stream.concat(Arrays.stream(name), Arrays.stream(ans)).toArray(String[]::new);
                outputStream.writeObject(both);
            }
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }

    public static void main(String[] args) {
        Client client = new Client();
    }
}

package pt.ubi.di.Model;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.ArrayList;

public class Client {

    private final String ip;
    private final int port;
    private final String connectionName;
    private Socket socket;
    private ObjectInputStream inputStream;
    private ObjectOutputStream outputStream;

    public Client(String ip, int port, String connectionName) {
        this.ip = ip;
        this.port = port;
        this.connectionName = connectionName;
        registerClient();
    }

    public Client() {
        this.ip = "127.0.0.1";
        this.port = 1234;
        this.connectionName = "Nameless";
        registerClient();
    }

    public void startConnection() {
        try {
            System.out.println("Start connection!");
            outputStream.writeObject(connectionName);
            System.out.println(inputStream.readObject());
            while (true) {
                System.out.println("Options available -> -list, -messages, -connect, -close and -help");
                String[] ans = Validations.readString().split(" ");
                switch (ans[0]) {
                    case "-help":
                    case "-list":
                    case "-messages":
                        outputStream.writeObject(ans);
                        System.out.println(inputStream.readObject());
                        break;
                    case "-connect":
                        outputStream.writeObject(ans);
                        break;
                    case "-close":
                        closeConnection();
                        return;
                }
            }
        } catch (IOException | ClassNotFoundException e) {
            System.out.println(e.getMessage());
        }
    }

    public void registerClient() {
        try {
            socket = new Socket(ip, port);
            inputStream = new ObjectInputStream(socket.getInputStream());
            outputStream = new ObjectOutputStream(socket.getOutputStream());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void closeConnection() {
        try {
            socket.close();
            outputStream.close();
            inputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String connectionAnotherClient(String clientName) {
        try {
            outputStream.writeObject(clientName);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        Client c = new Client("127.0.0.1", 1234, "another");
        c.startConnection();
    }
}


package pt.ubi.di.connection;

import pt.ubi.di.Model.ApplyClientConnection;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;

public class Server {
    private ServerSocket serverSocket;
    private Socket socket;
    private ArrayList<Connection> connectionsAvailable;

    /**
     * Constructor to create a normal server
     * @param port The port of the server
     */
    public Server(int port) {
        connectionsAvailable = new ArrayList<>();
        try {
            serverSocket = new ServerSocket(port);
            System.out.println("Waiting new connections!");
            while (true) {
                socket = serverSocket.accept();
                connectionsAvailable.add(new Connection(socket, connectionsAvailable));
            }
        } catch (IOException e) {
            System.out.println("Erro: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        Server server = new Server(1234);
    }
}

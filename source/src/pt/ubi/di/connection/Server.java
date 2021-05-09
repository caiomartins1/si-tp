package pt.ubi.di.connection;


import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;

public class Server {
    private ServerSocket serverSocket;
    private Socket socket;
    private ArrayList<Connection> connectionsAvailable;

    public Server(int port) {
        connectionsAvailable = new ArrayList<>();
        try {
            serverSocket = new ServerSocket(port);
            while (true) {
                System.out.println("Waiting new connections!");
                socket = serverSocket.accept();
                connectionsAvailable.add(new Connection(socket,connectionsAvailable));
            }
        } catch (IOException e) {
            System.out.println("Erro: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        Server server = new Server(1234);
    }
}

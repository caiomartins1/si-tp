package pt.ubi.di.Model;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;

public class Server {

    private ServerSocket serverSocket;
    private Socket socket;
    private ArrayList<Connection> connections;

    public Server(int port) {
        connections = new ArrayList<>();
        try {
            serverSocket = new ServerSocket(port);
            System.out.println("Waiting new connections!");
            while (true) {
                socket = serverSocket.accept();
                connections.add(new Connection(socket,connections));
                TimeUnit.SECONDS.sleep(2);
            }
        } catch (IOException | InterruptedException e) {
            System.out.println("Erro: " + e.getMessage());
        }
    }

    public static void main(String args[]) {
        Server server = new Server(1234);
    }
}

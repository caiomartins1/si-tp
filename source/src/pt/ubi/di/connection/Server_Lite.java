package pt.ubi.di.connection;


import pt.ubi.di.Model.Validations;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;


public class Server_Lite {
    private ServerSocket serverSocket;
    private Socket socket;
    private ObjectOutputStream outputStream;
    private ObjectInputStream inputStream;

    /**
     * Constructor to create a serve_lite,
     * responsible to create a new connection private between a server_lite and a client_lite
     * @param port the port of the connection
     */
    public Server_Lite(int port) {
        try {
            serverSocket = new ServerSocket(port);
            System.out.println("Another server created!");
            socket = serverSocket.accept();
            try {
                System.out.println("Socket accepted");
                outputStream = new ObjectOutputStream(socket.getOutputStream());
                inputStream = new ObjectInputStream(socket.getInputStream());
                while (true) {
                    System.out.println("Write the message!");
                    outputStream.writeObject(Validations.readString());
                }
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        } catch (IOException e) {
            System.out.println("Erro: " + e.getMessage());
        }
    }
}

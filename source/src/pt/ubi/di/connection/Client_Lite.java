package pt.ubi.di.connection;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

public class Client_Lite {
    private final String ip;
    private final int port;
    private Socket socket;
    private ObjectInputStream inputStream;
    private ObjectOutputStream outputStream;

    /**
     * Constructor to create a new client_lite,
     * responsible to create a new connection private between a server_lite and a client_lite
     * @param ip of the serve_lite
     * @param port of the connection
     */
    public Client_Lite(String ip, int port) {
        this.ip = ip;
        this.port = port;

        try {
            socket = new Socket(ip, port);
            inputStream = new ObjectInputStream(socket.getInputStream());
            outputStream = new ObjectOutputStream(socket.getOutputStream());
            System.out.println("Client created!");
            while (true) {
                System.out.println("Waiting message!");
                System.out.println("Message: " + inputStream.readObject());
            }
        } catch (IOException | ClassNotFoundException e) {
            System.out.println(e.getMessage());
        }
    }
}

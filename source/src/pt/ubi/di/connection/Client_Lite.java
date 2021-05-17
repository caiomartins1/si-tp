package pt.ubi.di.connection;

import pt.ubi.di.Model.Validations;
import pt.ubi.di.security.model.SecurityDH;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.Objects;

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
                System.out.print("Waiting for messages.....");

                String option =(String) inputStream.readObject();

                switch (option) {
                    case "dh":
                        SecurityDH a = (SecurityDH) inputStream.readObject();
                        SecurityDH b = new SecurityDH(a.getG(),a.getP(),false);
                        b.generateValues(false);
                        outputStream.writeObject(b);
                        b.generateKey(a.getX());
                        break;
                    default:
                        break;
                }
                /*System.out.println("Write the message!");
                outputStream.writeObject();*/
                /*System.out.println("Waiting message!");
                inputStream.readObject();*/
            }
        } catch (IOException | ClassNotFoundException e) {
            System.out.println(e.getMessage());
        }
    }
}

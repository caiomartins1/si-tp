package pt.ubi.di.Model;


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

    public Server_Lite(int port) {
        try {
            serverSocket = new ServerSocket(port);
            System.out.println("Another server created!");
            socket = serverSocket.accept();
            try {
                System.out.println("Socket accepted");
                outputStream = new ObjectOutputStream(socket.getOutputStream());
                inputStream = new ObjectInputStream(socket.getInputStream());
                while(true){
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

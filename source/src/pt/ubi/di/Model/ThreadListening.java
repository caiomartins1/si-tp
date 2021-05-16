package pt.ubi.di.Model;

import pt.ubi.di.connection.Connection;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.ArrayList;

public class ThreadListening extends Thread{

    private Socket socket;
    private ObjectOutputStream outputStream;
    private ObjectInputStream inputStream;
    private ArrayList<String> messages;
    private String connectionName;

    public ThreadListening(String connectionName, String ip, int port){
        super();
        this.connectionName = connectionName;
        try {
            socket = new Socket(ip, port);
            outputStream = new ObjectOutputStream(socket.getOutputStream());
            inputStream = new ObjectInputStream(socket.getInputStream());
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        start();
    }

    @Override
    public void run() {
        try{
            String[] ans = {"","-init", connectionName};
            outputStream.writeObject(ans);
            while(true){
                System.out.println("Waiting messages!");
                System.out.println((String) inputStream.readObject());
            }
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
}

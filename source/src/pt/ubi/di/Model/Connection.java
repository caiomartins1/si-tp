package pt.ubi.di.Model;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.ArrayList;

public class Connection extends Thread {
    private Socket socket;
    private String connectionName;
    private ObjectOutputStream outputStream;
    private ObjectInputStream inputStream;
    private ArrayList<Connection> connections;
    private ArrayList<String> messages = new ArrayList<>();


    /**
     * @param socket      the socket created in the server
     * @param connections the arraylist with all connections available in the server
     */
    public Connection(Socket socket, ArrayList<Connection> connections) {
        super();
        this.connectionName = "";
        this.socket = socket;
        this.connections = connections;
        try {
            outputStream = new ObjectOutputStream(socket.getOutputStream());
            inputStream = new ObjectInputStream(socket.getInputStream());
            connectionName = (String) inputStream.readObject();
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        start();
    }

    public void run() {
        try {
            //Confirm the connection with the client
            outputStream.writeObject("Connection Name: " + connectionName);
            outputStream.flush();
            while (true) {
                //System.out.println("Connected, waiting command!");
                String[] ans = (String[]) inputStream.readObject();
                switch (ans[0]) {
                    case "-connect":
                        Connection clientConnection = searchConnectionByName(ans[1]);
                        if (clientConnection != null) {
                            ArrayList<String> o = clientConnection.getMessages();
                            o.add("Client " + connectionName + " wants to connect with you!");
                        }
                        break;
                    case "-list":
                        outputStream.writeObject(listConnectionsAvailables());
                        break;
                    case "-close":
                        closeConnection();
                        break;
                    case "-messages":
                        String a = "";
                        for (String item:messages) {
                            a = a + item;
                        }
                        outputStream.writeObject(a);
                        break;
                    case "-help":
                        outputStream.writeObject("\nStandard commands\n" +
                                "-list -> list of all users connected in the serve\n" +
                                "-help -> show all the commands available\n" +
                                "-messages -> show the messages received from the serve or anothers clients\n" +
                                "-connect <connection name> -> send a message to <connection name> asking to make a channel\n" +
                                "-close -> close this connection with the server\n");
                        break;
                }
            }
        } catch (IOException e) {
            System.out.println("Error 1: " + e.getCause());
        } catch (ClassNotFoundException e) {
            System.out.println("Error 2: " + e.getCause());
        }
    }

    public void closeConnection() throws IOException {
        socket.close();
        inputStream.close();
        outputStream.close();
    }

    public ArrayList<String> getMessages() {
        return messages;
    }

    public String listConnectionsAvailables() {
        String list = "Connections available";
        for (Connection item : connections) {
            list = list + "\nConnection Name: " + item.getConnectionName() + ", IP:" + item.getSocket().getLocalAddress().toString().replace('/', ' ');
        }
        return list;
    }

    public Connection searchConnectionByName(String connectionName) {
        for (Connection item : connections) {
            System.out.println(item.getConnectionName());
            if (item.getConnectionName().equals(connectionName)) return item;
        }
        return null;
    }

    public Socket getSocket() {
        return socket;
    }

    public String getConnectionName() {
        return connectionName;
    }
}

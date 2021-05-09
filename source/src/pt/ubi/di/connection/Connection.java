package pt.ubi.di.connection;

import pt.ubi.di.Model.Client_Lite;
import pt.ubi.di.Model.Server_Lite;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;

public class Connection extends Thread {

    private Socket socket;
    private ObjectOutputStream outputStream;
    private ObjectInputStream inputStream;
    private ArrayList<Connection> connectionsAvailable;
    private ArrayList<String> messages;
    private String connectionName;

    public Connection(Socket socket, ArrayList<Connection> connectionsAvailable) {
        super();
        this.socket = socket;
        this.connectionsAvailable = connectionsAvailable;
        this.messages = new ArrayList<>();
        try {
            outputStream = new ObjectOutputStream(socket.getOutputStream());
            inputStream = new ObjectInputStream(socket.getInputStream());
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        start();
    }

    public void run() {
        try {
            while (true) {
                handleAction((String[]) inputStream.readObject());
            }
        } catch (IOException | ClassNotFoundException e) {
            System.out.println("Error: " + e.getCause());
        }
    }

    public void handleAction(String[] action) throws IOException {
        System.out.println("Action: " + action[1] + ", name: " + action[0]);
        switch (action[1]) {
            case "-init":
                init(action[2]);
                break;
            case "-help":
                help(action);
                break;
            case "-list":
                connectionsList(action);
                break;
            case "-connect":
                connectToAnotherClient(action);
                break;
            default:
                writeConnection(action,"Command '" + action[1] + "' not fold!");
                break;
        }
    }

    // =============================================================================

    public ArrayList<String> getMessages() {
        return messages;
    }

    public void setMessages(ArrayList<String> messages) {
        this.messages = messages;
    }

    public String getConnectionName() {
        return connectionName;
    }

    public void setConnectionName(String connectionName) {
        this.connectionName = connectionName;
    }

    public Socket getSocket() {
        return socket;
    }

    public void setSocket(Socket socket) {
        this.socket = socket;
    }

    public ObjectOutputStream getOutputStream() {
        return outputStream;
    }

    public void setOutputStream(ObjectOutputStream outputStream) {
        this.outputStream = outputStream;
    }

    public ObjectInputStream getInputStream() {
        return inputStream;
    }

    public void setInputStream(ObjectInputStream inputStream) {
        this.inputStream = inputStream;
    }
    // =============================================================================


    public void init(String connectionName) {
        System.out.println("Name: " + connectionName);
        this.connectionName = connectionName;
    }

    public void help(String[] action) {
        System.out.println("Entrou help");
        String text = "\nStandard commands\n\n" +
                "-list -> list of all users connected in the serve\n" +
                "-help -> show all the commands available\n" +
                "-messages -> show the messages received from the serve or anothers clients\n" +
                "-connect <connection name> -> send a message to <connection name> asking to make a channel\n";
        writeConnection(action, text);
    }

    public void connectionsList(String[] action) {
        String connections = "Users online in the server\n";
        int i = 1;
        for (Connection item : connectionsAvailable) {
            connections = connections + "(" + i + ") " + item.getConnectionName() + "\n";
            i++;
        }
        writeConnection(action, connections);
    }

    public void writeConnection(String[] action, String mensage) {
        try {
            System.out.println();
            Connection connection = findConnectionByName(action[0]);
            if(connection != null) connection.getOutputStream().writeObject(mensage);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public Connection findConnectionByName(String connectionName) {
        return connectionsAvailable.stream().filter(carnet -> connectionName.equals(carnet.getConnectionName())).findFirst().orElse(null);
    }

    public void connectToAnotherClient(String[] action) throws IOException {
        Connection connection1 = findConnectionByName(action[0]);
        Connection connection2 = findConnectionByName(this.connectionName);
        if (connection1 != null && connection2 != null) {
            String ip = socket.getInetAddress().getLocalHost().getHostAddress();
            System.out.println("Ip: " + ip);
            String menssage = "connect " + ip + " " + 1345;
            new ObjectOutputStream(connection1.getSocket().getOutputStream()).writeObject(menssage);
            System.out.println("End!");
        }
    }

}

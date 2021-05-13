package pt.ubi.di.connection;

import pt.ubi.di.Model.*;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.ArrayList;

public class Client {

    private final String ip;
    private final int port;
    private final String connectionName;
    private Socket socket;
    private ObjectInputStream inputStream;
    private ObjectOutputStream outputStream;

    //TODO: just to test
    public Client() {
        this.ip = "127.0.0.1";
        this.port = 1234;
        this.connectionName = "Nameless";
        try {
            socket = new Socket(ip, port);
            inputStream = new ObjectInputStream(socket.getInputStream());
            outputStream = new ObjectOutputStream(socket.getOutputStream());
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
        startConnection();
    }

    /**
     * Constructor to create the a class of type (CLIENT) client.
     *
     * @param ip             The ip of the server
     * @param port           The port open to connect to the server
     * @param connectionName The name of the connection
     */
    public Client(String ip, int port, String connectionName) {
        this.ip = ip;
        this.port = port;
        this.connectionName = connectionName;
        try {
            socket = new Socket(ip, port);
            inputStream = new ObjectInputStream(socket.getInputStream());
            outputStream = new ObjectOutputStream(socket.getOutputStream());
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
        startConnection();
    }

    // Initialize the client with the name in the connectionName
    public void startConnection() {
        String[] ans = {"-init", connectionName};
        try {
            outputStream.writeObject(ans);
            System.out.println(inputStream.readObject());
            while (true) {
                System.out.print("Command>");
                ans = Validations.readString().split(" ");
                outputStream.writeObject(ans);
                switch (ans[0]) {
                    case "-list":
                    case "-help":
                    case "-init":
                    case "-connect":
                        System.out.println(inputStream.readObject());
                        break;
                    case "-message":
                        ArrayList<ApplyClientConnection> aP = (ArrayList<ApplyClientConnection>) inputStream.readObject();
                        handleMessages(aP);
                        break;
                    default:
                        System.out.println("The command \"" + ans[0] + "\" not found!\nTry Again or use \"-help\"");
                        break;
                }
            }
        } catch (IOException | ClassNotFoundException e) {
            System.out.println(e.getMessage());
        }
    }

    /**
     * The function responsible to handle with client that want to create a new connection, TODO: pont-to-pont (Private)
     *
     * @param aP the list with the invites to make a connection pont-to-pont with another clients in the currently server,
     *           in this list the client can create the server and accept the invites.
     */
    public void handleMessages(ArrayList<ApplyClientConnection> aP) {
        if (aP.size() > 0) {
            for (ApplyClientConnection item : aP) {
                System.out.print(item.getMessage() + "(Y|N):");
                String a = Validations.readString();
                if (a.equals("Y")) {
                    if (item.getConnectionName().equals(connectionName)) {
                        System.out.println("Server on!");
                        Server_Lite sl = new Server_Lite(item.getPort());
                    } else {
                        System.out.println("Client on!");
                        Client_Lite cl = new Client_Lite(item.getIP(), item.getPort());
                    }
                }
            }
        } else {
            System.out.println("No messages!");
        }
    }

    public static void main(String[] args) {
        Client client = new Client();
    }
}

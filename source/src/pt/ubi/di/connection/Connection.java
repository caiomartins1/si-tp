package pt.ubi.di.connection;

import pt.ubi.di.Model.ApplyClientConnection;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.ArrayList;

public class Connection extends Thread {

    // The attribute of the class
    private Socket socket;
    private ObjectOutputStream outputStream;
    private ObjectInputStream inputStream;
    private ArrayList<Connection> connectionsAvailable;
    private String connectionName;
    private ArrayList<ApplyClientConnection> invites;
    private boolean working = true;

    /**
     * Constructor of the class Connection, this class is a Thread responsible to handle with the
     * new connection with the server (NORMAL).
     *
     * @param socket               Socket with the connection pre-establish in the Server
     * @param connectionsAvailable ArrayList with all connections available in the currently server
     */
    public Connection(Socket socket, ArrayList<Connection> connectionsAvailable) {
        super();
        this.socket = socket;
        this.connectionsAvailable = connectionsAvailable;
        this.invites = new ArrayList<>();
        connectionName = "Without name!";
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
            while (working) {
                handleAction((String[]) inputStream.readObject());
            }
        } catch (IOException | ClassNotFoundException e) {
            System.out.println("Error: " + e.getCause());
        }
    }

    /**
     * Function that handle with the input (received from the Client)
     *
     * @param action A array of String with the parameters received from the client
     * @throws IOException
     */
    public void handleAction(String[] action) throws IOException {
        switch (action[0]) {
            case "init" -> commandChangeConnectionName(action[1]);
            case "help" -> commandHelp();
            case "exit" -> commandExit();
            case "list" -> commandListOfUsers();
            case "connect" -> commandConnectToAnotherClient(action);
            case "invites" -> outputStream.writeObject(invites);
        }
    }

    /**
     * New command added, close the connection with the server and close the Thread
     * @throws IOException
     */
    private void commandExit() throws IOException {
        synchronized (connectionsAvailable){
            System.out.println("Connection \"" + connectionName +"\" disconnected!");
            connectionsAvailable.removeIf(c -> c.getConnectionName().equals(connectionName));
        }
        socket.close();
        outputStream.close();
        inputStream.close();
        working = false;
    }
    /**
     * Function responsible to change the name of the connection with the name received from the parameter
     *
     * @param connectionName The new nanme of the connection
     * @throws IOException
     */
    public void commandChangeConnectionName(String connectionName) throws IOException {
        this.connectionName = connectionName;
        outputStream.writeObject("Connection Name: " + connectionName);
    }

    //Send to the client the commands available
    public void commandHelp() throws IOException {
        String text =
                "Standard Commands =============================\n" +
                        "-list -> list of all users connected in the serve\n" +
                        "-init -> change the name of the connection\n" +
                        "-help -> show all the commands available\n" +
                        "-exit -> close the connection with the server\n" +
                        "-invites -> show the invites received from the serve or another clients\n" +
                        "-connect\n" +
                        "    ...   <connection name> -start -> send a message to <connection name> asking to make a channel and start the server\n" +
                        "    ...   <connection name> -> send a message to <connection name> asking to make a channel\n" +
                        "================================================";
        outputStream.writeObject(text);
    }

    //Send to the client the list of all users connect in the server
    public void commandListOfUsers() throws IOException {
        String text = "Users online in the server ======================\n";
        int i = 1;
        for (Connection item : connectionsAvailable) {
            text = text + "(" + i + ") " + item.getConnectionName() + "\n";
            i++;
        }
        text = text + "=================================================";
        outputStream.writeObject(text);
    }

    /**
     * Search in the arraylist the connection with the name received from the parameter
     * @param connectionName The name of the connection
     * @return the connection
     */
    public Connection findConnectionByName(String connectionName) {
        Connection cC = connectionsAvailable.stream().filter(carnet -> connectionName.equals(carnet.getConnectionName())).findFirst().orElse(null);
        if(cC.getConnectionName().equals(this.connectionName)){
            System.out.println("Connection1: " + cC.getConnectionName() + ", Connection2: " + connectionName);
            return null;
        }
        return cC;
    }

    /**
     * Function responsible to invite another client to create a private channel
     *
     * @param action variable with the name of the client that will be invite
     * @throws IOException
     */
    public void commandConnectToAnotherClient(String[] action) throws IOException {
        Connection connection1 = findConnectionByName(action[1]);
        if (connection1 != null) {
            String ip = socket.getInetAddress().getLocalHost().getHostAddress();

            String meClient = "The " + connectionName + " want to connect with you!";

            ApplyClientConnection aClient = new ApplyClientConnection(ip, 2222, meClient, connectionName);

            ArrayList<ApplyClientConnection> aC = connection1.getInvites();
            searchInvites(aClient, aC);
            synchronized (aC) {
                aC.add(aClient);
            }
            if (action.length == 2) {
                String meuServer = "You wanted to connect with " + connection1.getConnectionName() + " do you want to create the server?";
                ApplyClientConnection aServer = new ApplyClientConnection(ip, 2222, meuServer, connectionName);
                synchronized (invites) {
                    invites.add(aServer);
                }
            }
            outputStream.writeObject("The invite it was send with success!");
        } else {
            outputStream.writeObject("Client with the name \"" + action[1] + "\" not found or the client and the server is the same!");
        }
    }

    /**
     * Search if the client already have a invite from the same client, if has the old invite is
     * erase and a new invite is add in the arraylist with the invites.
     * @param aCC the new ApplyClientConnection created
     * @param aCCAl the arraylist with all invites sent to this client
     */
    public void searchInvites(ApplyClientConnection aCC, ArrayList<ApplyClientConnection> aCCAl) {
        for (ApplyClientConnection aux : aCCAl) {
            if (aux.getIP().equals(aCC.getIP())) {
                synchronized (aCCAl) {
                    aCCAl.remove(aux);
                }
            }
        }
    }

    // =============================================================================

    public ArrayList<ApplyClientConnection> getInvites() {
        return invites;
    }

    public void setInvites(ArrayList<ApplyClientConnection> invites) {
        this.invites = invites;
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

}

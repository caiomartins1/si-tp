package pt.ubi.di.connection;

import pt.ubi.di.Model.ApplyClientConnection;
import pt.ubi.di.Model.Validations;
import pt.ubi.di.security.model.PBKDF2;
import pt.ubi.di.security.model.SecurityDH;
import pt.ubi.di.security.model.SecurityUtil;

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
    private boolean working = true;

    //TODO: just to test
    public Client() {
        this.ip = "127.0.0.1";
        this.port = 1234;
        this.connectionName = "Alice";
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

    /**
     * Start the connection, wait the client type a command in the terminal to send the input to the server
     * TODO: now we can call several command in the same time as: -list -list -help -connect Alice, and will be call the server.
     */
    public void startConnection() {
        String[] ans = {"-init", connectionName};
        try {
            outputStream.writeObject(ans);
            System.out.println(inputStream.readObject());
            while (working) {
                System.out.print("Commands>");
                ans = Validations.readString().split(" ");
                outputStream.writeObject(ans);
                switch (ans[0]) {
                    case "-list":
                    case "-help":
                    case "-init":
                        System.out.println(inputStream.readObject());
                        break;
                    case "-connect":
                        int index = SecurityUtil.lookOptions(ans,new String[]{"-sk","-sessionKey","--sessionKey"});
                        if(index != -1)
                        {
                            byte[] key = SecurityUtil.shareSessionKeys(outputStream,inputStream,new String[]{});
                            System.out.println(">Session key sent to server: " + SecurityUtil.byteArrayToHex(key));
                        }
                        System.out.println(inputStream.readObject());
                        index = SecurityUtil.lookOptions(ans,new String[]{"-start"});
                        if(index != -1) {
                            Server_Lite sl = new Server_Lite(2222);
                        }
                        break;
                    case "-start"://Now we can start the connection in the same time we invite another client (if need help type -help in the terminal)
                        Server_Lite sl = new Server_Lite(2222);
                        break;
                    case "-exit": //Now we can close the connection
                        socket.close();
                        outputStream.close();
                        inputStream.close();
                        working = false;
                        break;
                    case "-invites":
                        ArrayList<ApplyClientConnection> aP = (ArrayList<ApplyClientConnection>) inputStream.readObject();
                        boolean useSK = inputStream.readBoolean();
                        handleMessages(aP, useSK);
                        break;
                    case "-pbk":
                        PBKDF2.handlePBKDFParams(ans);
                        break;
                    default:
                        System.out.println("The command \"-" + ans[0] + "\" not found!\nTry Again or use \"-help\"");
                        break;
                }
            }
//            }
        } catch (IOException | ClassNotFoundException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    /**
     * Valid the input received from the client
     * TODO: need to change this function because, in the moment it is used the "split("-")"  for some reason it is added in the ans the char "", with this function it is removed the char "".
     *
     * @param ans the strings separated with the "-"
     * @return return the ans without the char "" -> (char empty or null, i dont know what it is this)
     */
    private String[] validInputs(String[] ans) {
        String[] option = new String[ans.length - 1];
        int i = 0;
        for (String item : ans) {
            if (!item.equals("")) {
                option[i] = item;
                i++;
            }
        }
        return option;
    }

    /**
     * The function responsible to handle with client that want to create a new connection, TODO: pont-to-pont (Private)
     *
     * @param aP the list with the invites to make a connection pont-to-pont with another clients in the currently server,
     *           in this list the client can create the server and accept the invites.
     */
    public void handleMessages(ArrayList<ApplyClientConnection> aP, boolean useSK) {
        if (aP.size() > 0) {
            for (ApplyClientConnection item : aP) {
                System.out.print(item.getMessage() + "(Y|N):");
                String a = Validations.readString();
                if (a.equals("Y")) {
                    if (item.getConnectionName().equals(connectionName)) {
                        System.out.println("Server on!");
                        Server_Lite sl = new Server_Lite(item.getPort());
                    } else {
                        if(useSK) {
                            byte[] sessionKey = SecurityUtil.participateSessionKeys(outputStream,inputStream);
                            System.out.println(">Session Key received: " + SecurityUtil.byteArrayToHex(sessionKey));
                        }
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

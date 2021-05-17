package pt.ubi.di.connection;


import pt.ubi.di.Model.ApplyClientConnection;
import pt.ubi.di.Model.Validations;
import pt.ubi.di.security.model.MerklePuzzle;
import pt.ubi.di.security.model.SecurityDH;
import pt.ubi.di.security.model.SecurityMP;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Objects;


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
                    System.out.print("Private>");
                    String[] options = Objects.requireNonNull(Validations.readString()).split(" ");
                    switch (options[0]) {
                        case "-dh":
                            System.out.println("_____________Starting Diffie Hellman key exchange_____________");
                            outputStream.writeObject("dh");//inform KAP to use
                            SecurityDH factoryDH;
                            if(options.length<2)
                                factoryDH = new SecurityDH(1024,false);//TODO improve parameter (how it works)
                            else
                                factoryDH = new SecurityDH(Integer.parseInt(options[1]),false);
                            outputStream.writeObject(factoryDH);
                            SecurityDH resultDH = (SecurityDH) inputStream.readObject();
                            factoryDH.generateKey(resultDH.getX());
                            break;
                        case "-mkp":
                            System.out.println("_____________Starting Merkle Puzzles key exchange_____________");
                            outputStream.writeObject("mkp");//inform KAP to use
                            SecurityMP factoryMP = new SecurityMP();
                            outputStream.writeObject(factoryMP);
                            MerklePuzzle puzzleIndex = (MerklePuzzle) inputStream.readObject();
                            factoryMP.solveIndex(puzzleIndex);
                            break;
                        case "-help":
                            System.out.println(
                                    "help?...no."//TODO
                            );
                            break;
                        default:
                            System.out.println("The command \"" + options[0] + "\" not found!\nTry Again or use \"-help\"");
                            break;
                    }
                    /*System.out.println("Write the message!");
                    outputStream.writeObject();
                    System.out.println("Waiting message!");
                    inputStream.readObject();*/
                }
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}

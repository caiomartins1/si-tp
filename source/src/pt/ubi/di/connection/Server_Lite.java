package pt.ubi.di.connection;


import pt.ubi.di.Model.ApplyClientConnection;
import pt.ubi.di.Model.Validations;
import pt.ubi.di.security.model.MerklePuzzle;
import pt.ubi.di.security.model.SecurityDH;
import pt.ubi.di.security.model.SecurityMP;
import pt.ubi.di.security.model.SecurityUtil;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
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
                            SecurityDH.startExchange(outputStream,inputStream,options);
                            break;
                        case "-mkp":
                            outputStream.writeObject("mkp");//inform KAP to use
                            SecurityMP.startExchange(outputStream, inputStream);
                            break;
                        case "-sk"://-sk sizeOfKey -KAP(dh mkp or rsa)
                            outputStream.writeObject("sk");
                            //DH implementation
                            /*
                            byte[] sessionKey = SecurityUtil.generateNumber(Integer.parseInt(options[1]));
                            byte[] cipherKey =  SecurityDH.startExchange(outputStream,inputStream,options).toByteArray();
                            System.out.println("key:"+SecurityUtil.byteArrayToHex(cipherKey)+" SIZE: "+cipherKey.length);
                            byte[] cipher = SecurityUtil.encryptSecurity(sessionKey,cipherKey);
                            outputStream.writeObject(cipher);
                            System.out.println("SESSION KEY: "+SecurityUtil.byteArrayToHex(sessionKey));*/

                            byte[] sessionKey = SecurityUtil.generateNumber(Integer.parseInt(options[1]));
                            byte[] cipherKey = SecurityMP.startExchange(outputStream, inputStream);
                            byte[] cipher = SecurityUtil.encryptSecurity(sessionKey, cipherKey);
                            byte[] hmac = SecurityUtil.hmac(sessionKey);

                            outputStream.writeObject(cipher);
                            outputStream.writeObject(hmac);
                            System.out.println("SESSION KEY: "+SecurityUtil.byteArrayToHex(sessionKey));

                            break;
                        case "-help":
                            System.out.println(
                                    "help?...no."//TODO
                            );
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

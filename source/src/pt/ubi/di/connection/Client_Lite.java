package pt.ubi.di.connection;

import pt.ubi.di.Model.Validations;
import pt.ubi.di.security.model.MerklePuzzle;
import pt.ubi.di.security.model.SecurityDH;
import pt.ubi.di.security.model.SecurityMP;
import pt.ubi.di.security.model.SecurityRSA;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.math.BigInteger;
import java.util.*;

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
                System.out.print("Waiting for messages.....\n");
                String option =(String) inputStream.readObject();
                switch (option) {
                    case "dh":
                        System.out.println("_____________Starting Diffie Hellman key exchange_____________");
                        SecurityDH a = (SecurityDH) inputStream.readObject();
                        SecurityDH b = new SecurityDH(a.getG(),a.getP(),false);
                        b.generateValues(false);
                        outputStream.writeObject(b);
                        b.generateKey(a.getX());
                        break;
                    case "mkp":
                        System.out.println("_____________Starting Merkle Puzzles key exchange_____________");
                        SecurityMP factoryMP = (SecurityMP) inputStream.readObject();
                        SecurityMP resultMP = new SecurityMP(factoryMP.getPuzzles());
                        resultMP.encryptIndex();
                        outputStream.writeObject(resultMP.getFinalSolvedPuzzle());
                        break;
                    case "rsa":
                        System.out.println("_____________Starting RSA key exchange_____________");

                        //gera as chaves RSA do Cliente
                        SecurityRSA factoryRSA = new SecurityRSA(1024,false);
                        factoryRSA.calculate_Keys();

                        //envia a pk para o outro cliente
                        SecurityRSA publickey = new SecurityRSA(factoryRSA.getE(),factoryRSA.getN());
                        outputStream.writeObject(publickey);

                        //recebe a pk outro Cliente
                        SecurityRSA factoryRSA_1 = (SecurityRSA) inputStream.readObject();
                        System.out.println(factoryRSA_1.getE() +"\n 2- "+ factoryRSA_1.getN());
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

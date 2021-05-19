package pt.ubi.di.connection;

import pt.ubi.di.Model.Validations;
import pt.ubi.di.security.model.MerklePuzzle;
import pt.ubi.di.security.model.SecurityDH;
import pt.ubi.di.security.model.SecurityMP;
import pt.ubi.di.security.model.SecurityUtil;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.Arrays;
import java.util.Objects;

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
                        byte[] keyDH = SecurityDH.receiveExchange(outputStream,inputStream);
                        System.out.println("Key generated by Diffie-Hellman:\n" + SecurityUtil.byteArrayToHex(keyDH));
                        break;
                    case "mkp":
                        byte[] keyMP = SecurityMP.receiveExchange(outputStream, inputStream);
                        System.out.println("Key generated by Merkle Puzzles:\n" + SecurityUtil.byteArrayToHex(keyMP));
                        break;
                    case "sk":
                        //DH implementation
                        /*byte[] cipherKey =  SecurityDH.receiveExchange(outputStream,inputStream).toByteArray();
                        byte[] cipher = (byte[]) inputStream.readObject();
                        byte[] sessionKey = SecurityUtil.decipherSecurity(cipher,cipherKey);
                        System.out.println("SESSION KEY: "+SecurityUtil.byteArrayToHex(sessionKey));*/

                        //MKP implementation
                        /*System.out.println("Entrei Sk");
                        byte[] cipherKey = SecurityMP.receiveExchange(outputStream, inputStream);
                        byte[] cipher = (byte[]) inputStream.readObject();
                        System.out.println("cipherO: "+Arrays.toString(cipher) + " SIZE: " + cipher.length);
                        System.out.println("cipherS: "+SecurityUtil.byteArrayToString(cipher));
                        cipher[1] =(byte) 0;
                        System.out.println("cipherA: "+ Arrays.toString(cipher) + " SIZE: " + cipher.length);
                        System.out.println("cipherS: "+SecurityUtil.byteArrayToString(cipher));
                        byte[] hmac = (byte[]) inputStream.readObject();
                        byte[] sessionKey = SecurityUtil.decipherSecurity(cipher, cipherKey);
                        System.out.println("cipher4: "+SecurityUtil.byteArrayToHex(sessionKey) + " SIZE: " + sessionKey.length);
                        System.out.println("cipherS: "+SecurityUtil.byteArrayToString(sessionKey));
                        if (!SecurityUtil.hmacCheck(hmac, sessionKey)) {
                            System.out.println("UIUI");
                        } else {
                            System.out.println("SESSION KEY: "+SecurityUtil.byteArrayToHex(sessionKey));
                        }*/



                        break;
                    case "exit":
                        socket.close();
                        break;
                    default:
                        break;
                }
            }
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}

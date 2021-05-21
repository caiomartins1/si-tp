package pt.ubi.di.connection;


import pt.ubi.di.Model.Validations;
import pt.ubi.di.security.model.SecurityDH;
import pt.ubi.di.security.model.SecurityMP;
import pt.ubi.di.security.model.SecurityRSA;
import pt.ubi.di.security.model.SecurityUtil;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Objects;


public class Server_Lite {
    private ServerSocket serverSocket;
    private Socket socket;
    private ObjectOutputStream outputStream;
    private ObjectInputStream inputStream;
    private byte[] secretKey = null;

    public Server_Lite(int port) {
        this(port,null);
    }

    /**
     * Constructor to create a serve_lite,
     * responsible to create a new connection private between a server_lite and a client_lite
     * @param port the port of the connection
     */
    public Server_Lite(int port, byte[] key) {
        this.secretKey = key;
        try {
            serverSocket = new ServerSocket(port);
            socket = serverSocket.accept();
            try {
                System.out.println("Server created!");
                int index = -1;
                outputStream = new ObjectOutputStream(socket.getOutputStream());
                inputStream = new ObjectInputStream(socket.getInputStream());
                while (true) {
                    System.out.print("Private>");
                    String[] options = Objects.requireNonNull(Validations.readString()).split(" ");
                    switch (options[0]) {
                        case "-dh":
                            index = SecurityUtil.lookOptions(options, new String[]{"help","-help","--help","-h","--h"});
                            if(index!=-1)
                                SecurityDH.help();
                            else {
                                outputStream.writeObject("dh");
                                secretKey = SecurityDH.startExchange(outputStream,inputStream, options);
                                System.out.println(">Key generated by Diffie-Hellman:\n" + SecurityUtil.byteArrayToHex(secretKey));
                            }
                            break;
                        case "-mkp":
                            index = SecurityUtil.lookOptions(options, new String[]{"help","-help","--help","-h","--h"});
                            if(index!=-1)
                                SecurityMP.help();
                            else {
                                outputStream.writeObject("mkp");
                                secretKey = SecurityMP.startExchange(outputStream, inputStream, options);
                                System.out.println(">Key generated by Merkle Puzzle:\n" + SecurityUtil.byteArrayToHex(secretKey));
                            }
                            break;
                        case "-sk":
                            index = SecurityUtil.lookOptions(options, new String[]{"help","-help","--help","-h","--h"});
                            if(index!=-1)
                                SecurityUtil.shareSessionHelp();
                            else {
                                outputStream.writeObject("sk");
                                secretKey= SecurityUtil.shareSessionKeys(outputStream, inputStream, options);
                                System.out.println(">Session key generated: " + SecurityUtil.byteArrayToHex(secretKey));
                            }
                            break;
                        case "-ck":
                            outputStream.writeObject("ck");
                            System.out.println(">Starting key check...");
                            if(secretKey == null) {
                                System.out.println("No secret key configured.");
                            }
                            else
                                SecurityUtil.checkSharedKey(outputStream,inputStream,secretKey);
                            break;
                        case "-message":
                            outputStream.writeObject("message");
                            communicate();
                            break;
                        case "-rsa":
                            index = SecurityUtil.lookOptions(options, new String[]{"help","-help","--help","-h","--h"});
                            if(index!=-1)
                                SecurityRSA.help();
                            else {
                                //demora um pouco
                                System.out.println("_____________Starting RSA key exchange_____________");
                                outputStream.writeObject("rsa");

                                //pk do outro Cliente
                                SecurityRSA factoryRSA_1 = (SecurityRSA)inputStream.readObject();

                                //gera as suas chaves de modo a poder enviar mensagens encriptadas
                                SecurityRSA factoryRSA = new SecurityRSA();
                                factoryRSA.calculate_Keys();
                                System.out.println("My Public Key: "+ factoryRSA.getE() + "\nMy Private Key: " + factoryRSA.getD());

                                //escreve e envia a sua chave pública do Cliente - usa para encriptar mensagens a enviar
                                SecurityRSA publicKey = new SecurityRSA(factoryRSA.getE(),factoryRSA.getN());
                                outputStream.writeObject(publicKey);

                                System.out.println("-------------------------------------------");
                                System.out.println("Public Key do outro User -> " + factoryRSA_1.getE());
                            }
                            break;
                        case "-help":
                            System.out.println(
                                    """
                                            Commands ===================================================================
                                            -dh, Diffie-Hellman Key-agreement protocol
                                            -mkp, Merkle Puzzle Key-agreement protocol
                                            -sk, share a session key by using a KAP
                                            -ck, use hmac to verify if the shared secret key is the same
                                            -message, send encrypted message between each other
                                            -rsa, share messages using RSA - public and secret key
                                            Type -\033[3moption\033[0m help -help --help -h --h, for more information regarding each option
                                            ============================================================================
                                            """
                            );
                            break;
                        case "-exit":
                            outputStream.writeObject("exit");
                            outputStream.close();
                            inputStream.close();
                            socket.close();
                        default:
                            System.out.println("The command \"" + options[0] + "\" not found!\nTry Again or use \"-help\"");
                            break;
                    }
                }
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }
        } catch (IOException e) {
            System.out.println("Error on accepting connection: " + e.getMessage());
        }
    }

    private void communicate() {
        boolean flag = true;
        if(secretKey == null) {
            System.out.println("No secret key configured.");
            return;
        }
        System.out.print("message>");
        while(true) {
                String message = Validations.readString();
                    try {
                        if (message == null)
                            message = "";
                        else if (message.equals("-exit")) {
                            outputStream.writeObject(false);
                            return;
                        }
                        outputStream.writeObject(true);
                    } catch (Exception e) {
                        System.out.println("Error sending flag.");;
                    }
                SecurityUtil.sendMessage(outputStream,inputStream,message,secretKey,new String[]{});
                try {
                    flag =(boolean) inputStream.readObject();
                    if (!flag)
                        return;
                } catch (Exception e) {
                    System.out.println("Error Receiving flag.");;
                }
                String receiveMessage = SecurityUtil.receiveMessage(outputStream,inputStream,secretKey);
                System.out.println(receiveMessage);
                System.out.print("message>");
            }
    }

}

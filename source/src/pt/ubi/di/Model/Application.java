package pt.ubi.di.Model;

import pt.ubi.di.Model.Validations;
import pt.ubi.di.connection.Client;
import pt.ubi.di.connection.Server;
import pt.ubi.di.security.model.MerklePuzzle;
import pt.ubi.di.security.model.SecurityDH;
import pt.ubi.di.security.model.SecurityMP;
import pt.ubi.di.security.model.SecurityUtil;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

public class Application {
    public static void main(String[] args) {
        /*String ip = "127.0.0.1";
        int port = 1234;
        String name = "Vinícius";
        Client c = new Client(ip, port, name);*/

        /*SecurityMP a = new SecurityMP(1,16);*/

        /*SecurityDH a = new SecurityDH(255,false);
        SecurityDH b = new SecurityDH(a.getG(),a.getP(),false);
        a.generateValues(false);
        b.generateValues(false);
        a.generateKey(b.getX());
        b.generateKey(a.getX());
        System.out.println("KEY: "+ SecurityUtil.byteArrayToHex(a.getK().toByteArray()) +" SIZE: " + a.getK().toByteArray().length);
        System.out.println("KEY: "+ SecurityUtil.byteArrayToHex(b.getK().toByteArray())+" SIZE: " + b.getK().toByteArray().length);*/


        /**
         * Input received from the keyboard
         * */
        String[] option;

        /**
         * Name of the client, IP of the server, PORT the port of the server
         */
        String name = "",ip = "",port = "";

        /**
         * It is use to control the loop of the application
         */
        boolean working = true;


        System.out.println("Application Started!");
        while (working) {
            option = Validations.readString().split("-");
            for (String op : option) {
                String[] o = op.split(" ");
                if (o[0].equals("name") && o.length == 2) {
                    name = o[1];
                } else if (o[0].equals("ip") && o.length == 2) {
                    ip = o[1];
                } else if (o[0].equals("port") && o.length == 2) {
                    port = o[1];
                }
            }
            if(option.length <= 1){
                System.out.println("Command not found!\nTry Again or use \"-help\"");
                continue;
            }
            switch (option[1].trim()) {
                case "setup server":
                    if (port.equals("")) {
                        System.out.println("<!ALERT!>\nTo connect to a server it is necessary the -port!\nPlease try to give the -port.");
                        break;
                    }
                    if (!Validations.tryParsing(port)) {
                        System.out.println("<!ALERT!>\nThe port \"" + port + "\" it is not valid!\nPlease try with another port!");
                        break;
                    }
                    if (!Validations.portAvailable(Integer.parseInt(port))) {
                        System.out.println("<!ALERT!>\nThe port \"" + port + "\" it is not available!\nPlease try with another port!");
                        break;
                    }
                    System.out.println("PORT: " + port);
                    Server s = new Server(Integer.parseInt(port));
                    break;

                case "setup client":
                    //System.out.println("Name: " + name + ", IP: " + ip + ", PORT: " + port);
                    if (port.equals("") && ip.equals("")) {
                        System.out.println("<!ALERT!>\nTo connect to a server it is necessary the -port and the -ip\nPlease try to give the -port and the -ip.");
                        break;
                    }
                    if (!Validations.tryParsing(port)) {
                        System.out.println("<!ALERT!>\nThe port \"" + port + "\" it is not valid!\nPlease try with another port!");
                        break;
                    }
                    if (!Validations.checkIPv4(ip)) {
                        System.out.println("<!ALERT!>\nThe IP \"" + ip + "\" it is not valid!\nPlease try with another IP.");
                        break;
                    }
                    /*if (!Validations.serverListening(ip, Integer.parseInt(port))) {
                        System.out.println("<!ALERT!>\nThere is no open server with this IP and PORT!\nPlease try with another PORT or IP.");
                        break;
                    }*/

                    Client c = new Client(ip, Integer.parseInt(port), name);
                    break; //-setup client -ip 127.0.0.1 -port 1234 -name vinicius
                case "help":
                    System.out.println("""
                            Standard Commands =============================
                            -setup client -> initializing the client to connect to a server
                                  ...     -ip -> the ip of the server
                                  ...     -port the port that the client will connect
                                  ...     -name the your username (optional)
                            -setup server -> initializing the server with the port <port>
                                  ...     -port the port of the server
                            -help -> show all the options available
                            -exit -> close the application
                            ================================================""");
                    break;
                case "exit":
                    System.out.println("Application closing...");
                    working = false;
                    break;
                default:
                    System.out.println("The command \"-" + option[1] + "\" not found!\nTry Again or use \"-help\"");
                    break;
            }
        }
    }
}
// If you want to test
//-setup server -port 1234 //TO create a server
//-setup client -ip 127.0.0.1 -port 1234 -name Vinicius //To create a client with the name Vinicius
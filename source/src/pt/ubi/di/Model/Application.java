package pt.ubi.di.Model;

import pt.ubi.di.Model.Validations;
import pt.ubi.di.connection.Client;
import pt.ubi.di.security.model.MerklePuzzle;
import pt.ubi.di.security.model.SecurityDH;
import pt.ubi.di.security.model.SecurityMP;
import pt.ubi.di.security.model.SecurityUtil;

public class Application {
    public static void main(String[] args) {
        /*String ip = "127.0.0.1";
        int port = 1234;
        String name = "Vinícius";
        Client c = new Client(ip, port, name);*/

        SecurityMP a = new SecurityMP(1,16);

        /*SecurityDH a = new SecurityDH(255,false);
        SecurityDH b = new SecurityDH(a.getG(),a.getP(),false);
        a.generateValues(false);
        b.generateValues(false);
        a.generateKey(b.getX());
        b.generateKey(a.getX());
        System.out.println("KEY: "+ SecurityUtil.byteArrayToHex(a.getK().toByteArray()) +" SIZE: " + a.getK().toByteArray().length);
        System.out.println("KEY: "+ SecurityUtil.byteArrayToHex(b.getK().toByteArray())+" SIZE: " + b.getK().toByteArray().length);*/



    }
}

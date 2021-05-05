package pt.ubi.di;

import pt.ubi.di.Model.*;
import pt.ubi.di.security.model.SecurityDH;
import pt.ubi.di.security.model.SecurityUtil;

import java.math.BigInteger;

public class Aplicacao {
    public static void main(String[] args) {
        System.out.println("======================================");
        System.out.println("===============Opção==================");
        System.out.println("======== (1) Cliente =================");
        System.out.println("======== (2) Servidor ================");
        System.out.println("======== (3) Sair ====================");
        System.out.println("======================================");
        //String answer = Validations.readString();
        String answer = "3";

        ;

        switch(answer){
            case "1":
                Cliente c = new Cliente();
                break;
            case "2":
                Servidor servidor = new Servidor();
                servidor.ConectarCliente(2222);
                break;
            case "3":
                /*Exemple test
                SecurityDH based = new SecurityDH(4096,false);
                SecurityDH based2 = new SecurityDH(based.getG(),based.getP());
                based.generateValues(false);
                based2.generateValues(false);

                based.generateKey(based2.getX());
                based2.generateKey(based.getX());*/

                break;
        }
    }
}

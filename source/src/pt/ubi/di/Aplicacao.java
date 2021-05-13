package pt.ubi.di;

import pt.ubi.di.Model.*;
import pt.ubi.di.security.model.SecurityDH;
import pt.ubi.di.security.model.SecurityMP;
import pt.ubi.di.security.model.SecurityUtil;

import java.lang.reflect.Array;
import java.math.BigInteger;
import java.util.Arrays;

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
                SecurityMP aa = new SecurityMP(1);
                break;
        }
    }
}

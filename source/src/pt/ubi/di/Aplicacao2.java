package pt.ubi.di;

import pt.ubi.di.Model.*;

public class Aplicacao2 {
    public static void main(String[] args) {

        System.out.println("======================================");
        System.out.println("============== Opção =================");
        System.out.println("======== (1) Cliente =================");
        System.out.println("======== (2) Servidor ================");
        System.out.println("======== (3) Sair ====================");
        System.out.println("======================================");
        String answer = Validations.readString();

        switch (answer) {
            case "1":
                Cliente c = new Cliente();
                break;
            case "2":
                Servidor servidor = new Servidor();
                servidor.ConectarCliente(2222);
                break;
            case "3":
                break;
        }
    }
}

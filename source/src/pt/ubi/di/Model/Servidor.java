package pt.ubi.di.Model;

import pt.ubi.di.Model.*;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class Servidor {

    public void ConectarCliente(int port)
    {
        ServerSocket meuServidor = null;
        Socket sServidor = null;

        while (true)
        {
            try
            {
                System.out.println("Esperando cliente!");
                meuServidor = new ServerSocket(port);
                sServidor = meuServidor.accept();

                System.out.println("Cliente encontrado!\n");
                ObjectOutputStream out = new ObjectOutputStream(sServidor.getOutputStream());
                ObjectInputStream in = new ObjectInputStream(sServidor.getInputStream());
                while (true)
                {
                    //Recebe a mensagem do cliente ============================================
                    Object answer = in.readObject();
                    System.out.println("Mensagem do cliente: " + answer);
                    System.out.println("Escreva uma mensagem: ");
                    out.flush();
                    answer = Validations.readString();
                    if (answer.toString().equals("fim"))
                    {
                        System.out.println("Conexão terminada!\n");
                        //Fechar os sockets ====================================================
                        sServidor.close();
                        meuServidor.close();
                        out.close();
                        in.close();
                        break;
                    }
                    System.out.println("Mensagem enviada!\nEsperando resposta!");
                }
            }
            catch (Exception e)
            {
                System.out.println("Erro: " + e.getMessage());
            }
        }
    }
}

package pt.ubi.di.Model;

import pt.ubi.di.Model.*;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

public class Cliente
{
    public Cliente()
    {
        try
        {
            Socket sc = new Socket("127.0.0.1", 2222);
            String answer = "";

            ObjectOutputStream out = new ObjectOutputStream(sc.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(sc.getInputStream());

            while(true)
            {
                //Envia a mensagem para os servidor =========================================
                System.out.print("Escreva uma mensagem: ");
                answer = Validations.readString();
                out.writeObject(answer);
                System.out.println("Mensagem enviada!");
                //Recebe a mensagem do servidor =============================================
                answer = (String) in.readObject();
                if(answer.equals("sair"))
                {
                    System.out.println("Conexão terminada!");
                    //Fecha os sockets ========================================================
                    sc.close();
                    out.flush();
                    break;
                }
                System.out.println("Mensagem recebida: " + answer);
            }
        }
        catch (Exception e)
        {
            System.out.println("Erro: " + e.getMessage());
        }
    }
}

package pt.ubi.di.Model;

import pt.ubi.di.Model.Validations;
import pt.ubi.di.connection.Client;
import pt.ubi.di.security.model.MerklePuzzle;
import pt.ubi.di.security.model.SecurityMP;

public class Application {
    public static void main(String[] args) {
        /*String ip = "127.0.0.1";
        int port = 1234;
        String name = "Name";
        Client c = new Client(ip, port, name);//commented*/

        SecurityMP x =new SecurityMP(10,16,4,2,true);
        SecurityMP y =new SecurityMP(x.getPuzzles());
        y.encryptIndex();
        x.solveIndex(y.getFinalSolvedPuzzle());
    }
}

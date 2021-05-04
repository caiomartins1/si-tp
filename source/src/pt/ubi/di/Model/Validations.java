package pt.ubi.di.Model;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class Validations {

    public static String readString ()
    {
        BufferedReader canal;
        canal = new BufferedReader ( new InputStreamReader(System.in));
        try
        {
            return canal.readLine();
        }
        catch (IOException ex)
        {
            return null;
        }
    }
}

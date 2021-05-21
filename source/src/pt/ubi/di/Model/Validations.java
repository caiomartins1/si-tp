package pt.ubi.di.Model;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

public class Validations {

    public static String readString()
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

    public static boolean checkIPv4(final String ip) {
        boolean isIPv4;
        try {
            final InetAddress inet = InetAddress.getByName(ip);
            isIPv4 = inet.getHostAddress().equals(ip)
                    && inet instanceof Inet4Address;
        } catch (final UnknownHostException e) {
            isIPv4 = false;
        }
        return isIPv4;
    }

    public static boolean serverListening(String host, int port)
    {
        Socket s = null;
        try
        {
            s = new Socket(host, port);
        }
        catch (Exception e)
        {
            return false;
        }
        finally
        {
            if(s != null)
                try {s.close();}
                catch(Exception e){}
        }
        return true;
    }

    public static boolean tryParsing(String port){
        try{
            int ans = Integer.parseInt(port);
            System.out.println(ans);
            if(ans > 65536 || ans < 1){
                return false;
            }
        }catch(NumberFormatException e){
            return false;
        }
        return true;
    }
    public static boolean portAvailable(int port) {
        try (Socket ignored = new Socket("127.0.0.1", port)) {
            return false;
        } catch (IOException ignored) {
            return true;
        }
    }

    public static String[] input(String option){
        String[] ans = option.split("-");
        System.out.println(": " + option + ", " + ans[0]);
        String[] ansAux = new String[ans.length];
        int i = 0;
        for (String op: ans){
            if(i>0){
                ansAux[i] = op;
                i++;
            }
        }
        System.out.println("ola2: " +ans[0]);
        return ansAux;
    }
}

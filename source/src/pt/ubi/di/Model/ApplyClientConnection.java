package pt.ubi.di.Model;

import java.io.Serializable;

public class ApplyClientConnection implements Serializable {

    private String IP;
    private int Port;
    private String Message;
    private String ConnectionName;

    public ApplyClientConnection(String IP, int port, String message, String connectionName) {
        this.IP = IP;
        Port = port;
        Message = message;
        ConnectionName = connectionName;
    }

    public String getIP() {
        return IP;
    }

    public void setIP(String IP) {
        this.IP = IP;
    }

    public int getPort() {
        return Port;
    }

    public void setPort(int port) {
        Port = port;
    }

    public String getMessage() {
        return Message;
    }

    public void setMessage(String message) {
        Message = message;
    }

    public String getConnectionName() {
        return ConnectionName;
    }

    public void setConnectionName(String connectionName) {
        ConnectionName = connectionName;
    }

    @Override
    public boolean equals(Object obj) {
        if(obj.getClass().getSimpleName().equals((ApplyClientConnection.class).getSimpleName())){
            return ((ApplyClientConnection) obj).getConnectionName().equals(ConnectionName) &&
                    ((ApplyClientConnection) obj).getIP().equals(IP) &&
                    ((ApplyClientConnection) obj).getMessage().equals(Message) &&
                    ((ApplyClientConnection) obj).getPort() == Port;
        }
        return false;
    }
}

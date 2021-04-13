package il.ac.idc.cs.sinkhole;

import java.net.*;

public class UDPServer {
    private DatagramSocket serverSocket;
    private InetAddress address;
    private int port;
    private static final int defaultPacketLength = 1024;

    public DatagramPacket Listen(int port) throws Exception {
        serverSocket = new DatagramSocket(port);
        byte[] receiveData = new byte[defaultPacketLength];
        DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
        serverSocket.receive(receivePacket);
        this.port = receivePacket.getPort();
        address = receivePacket.getAddress();
        return receivePacket;
    }

    public void returnDNSQueryResultToUser(byte[] result, int length) throws Exception {
        DatagramPacket sendPacket = new DatagramPacket(result, length, address, this.port);
        serverSocket.send(sendPacket);
        serverSocket.close();
    }

}




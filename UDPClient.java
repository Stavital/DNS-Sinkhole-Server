package il.ac.idc.cs.sinkhole;

import java.net.*;
import java.util.Arrays;

public class UDPClient {
    private static final int defaultPacketLength = 1024;
    private static final int dnsServerPort = 53;

    public DatagramPacket doDNSQueryIteration(DatagramPacket dnsQuery, String IPAddressAsStr) throws Exception {
        DatagramSocket clientSocket = new DatagramSocket();
        InetAddress IPAddress = InetAddress.getByName(IPAddressAsStr);
        byte[] receiveData = new byte[defaultPacketLength];

        DatagramPacket sendPacket = new DatagramPacket(dnsQuery.getData(), dnsQuery.getLength(), IPAddress, dnsServerPort);
        clientSocket.send(sendPacket);

        DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);

        clientSocket.receive(receivePacket);
        clientSocket.close();
        return receivePacket;
    }
}



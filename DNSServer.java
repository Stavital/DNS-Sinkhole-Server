package il.ac.idc.cs.sinkhole;

import javax.sound.sampled.AudioFormat;
import java.lang.reflect.Array;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.util.*;

public class DNSServer {
    private UDPClient client = new UDPClient();
    private UDPServer server = new UDPServer();
    static final String[] rootServers = {"a.root-servers.net", "b.root-servers.net", "c.root-servers.net", "d.root-servers.net",
            "e.root-servers.net", "f.root-servers.net", "g.root-servers.net", "h.root-servers.net",
            "i.root-servers.net", "j.root-servers.net", "k.root-servers.net", "l.root-servers.net", "m.root-servers.net"};
    static final int portNum = 5300;
    static final int byteSize = 8;
    static final int halfByteSize = 4;
    static final int headerLength = 12;
    static final char dot = '.';
    static final int startOfFlagsIndex = 2;
    static final int RcodeIndex = 3;
    static final int ansCountMSB = 6;
    static final int ansCountLSB = 7;
    static final int authCountMSB = 8;
    static final int authCountLSB = 9;
    static final int typeAndClassFieldsLengthFromQuestion = 4;
    static final int bytesInAuthUntilRDLengt = 10;
    static final int pointerByteMaxVal = -64;
    static final int maxIterationCount = 16;


    public void DoMainLogic(HashSet<String> forbiddenHosts) {
        DatagramPacket DNSQueryResponse;

        try {
            while (true) {
                int numIter = 0;
                DatagramPacket clientDNSQuery = server.Listen(portNum);
                byte[] clientDNSQueryAsBytes = clientDNSQuery.getData();
                String rootHostName = RandomlySelectRootServer();
                String wantedHost = GetWantedHost(clientDNSQueryAsBytes);
                if (forbiddenHosts.contains(wantedHost)) {
                    returnNxDomainErrorToClient(clientDNSQuery);
                    continue;
                }

                DNSQueryResponse = client.doDNSQueryIteration(clientDNSQuery, rootHostName);
                byte[] DNSQueryResponseAsBytes = DNSQueryResponse.getData();
                int RCode;
                RCode = DNSQueryResponseAsBytes[RcodeIndex] << halfByteSize;
                RCode = RCode >> halfByteSize;
                if (RCode != 0) {
                    ReturnQueryAnswerToClient(DNSQueryResponse);
                    continue;
                }

                int ansCount;
                int authCount;

                do {
                    String nextAddress = GetFirstNameServerInAuthoritySection(DNSQueryResponseAsBytes);
                    numIter++;
                    DNSQueryResponse = client.doDNSQueryIteration(clientDNSQuery, nextAddress);
                    DNSQueryResponseAsBytes = DNSQueryResponse.getData();
                    RCode = DNSQueryResponseAsBytes[RcodeIndex] << halfByteSize;
                    RCode = RCode >> halfByteSize;
                    ansCount = getCount(DNSQueryResponseAsBytes, ansCountMSB, ansCountLSB);
                    authCount = getCount(DNSQueryResponseAsBytes, authCountMSB, authCountLSB);
                } while (RCode == 0 && ansCount == 0 && authCount > 0 && numIter < maxIterationCount);

                ReturnQueryAnswerToClient(DNSQueryResponse);

            }
        } catch (Exception e) {
            System.err.println(e);
        }
    }

    private static int getCount(byte[] query, int MSB, int LSB) {
        int countMSBs = query[MSB] << byteSize;
        int countLSBs = query[LSB];
        return (countMSBs | countLSBs);
    }

    private static String RandomlySelectRootServer() {
        int randNum = (int) (Math.random() * rootServers.length);
        return rootServers[randNum];
    }

    // gets the query response and extracts from it the next DNS server that we need to ask the query
    private static String GetFirstNameServerInAuthoritySection(byte[] responseAsBytes) {
        int numBytesToSkip = headerLength;
        int i = numBytesToSkip; //skip the label count byte
        while (responseAsBytes[i] != 0) {
            i++;
        }
        int numBytesToSkipFromQuery = i + typeAndClassFieldsLengthFromQuestion;// question + type + class
        int numBytesToSkipFromAuth = bytesInAuthUntilRDLengt; //until RDlength
        int RDLengthIndex = numBytesToSkipFromAuth + numBytesToSkipFromQuery;
        RDLengthIndex++;
        int RDLengthMSB = responseAsBytes[RDLengthIndex];
        RDLengthMSB = RDLengthMSB << byteSize;
        RDLengthIndex++;
        int RDLengthLSB = responseAsBytes[RDLengthIndex];
        int RDLength = RDLengthMSB | RDLengthLSB;

        int iterator = RDLengthIndex + 1;
        StringBuilder nextHost = new StringBuilder();
        int curByte = responseAsBytes[iterator];
        RDLength--;

        while (curByte > pointerByteMaxVal && RDLength > 0) {
            int numOfCharToRead = curByte;
            while (numOfCharToRead > 0) {
                iterator++;
                nextHost.append((char) responseAsBytes[iterator]);
                numOfCharToRead--;
                RDLength--;
            }
            nextHost.append(dot);
            iterator++;
            curByte = responseAsBytes[iterator];
            RDLength--;
        }
        nextHost.deleteCharAt(nextHost.length() - 1);

        if (curByte <= pointerByteMaxVal && RDLength > 0) {
            nextHost.append(dot);
            int offsetMSB = curByte;
            offsetMSB = offsetMSB & 0x3f; //remove the '11' flag
            offsetMSB = offsetMSB >>> 2;
            offsetMSB = offsetMSB << byteSize;
            iterator++;
            int offsetLSB = responseAsBytes[iterator];
            int offset = offsetMSB | offsetLSB;

            iterator = offset;
            curByte = responseAsBytes[iterator];

            while (curByte != 0) {
                int numOfCharToRead = curByte;
                while (numOfCharToRead > 0) {
                    iterator++;
                    nextHost.append((char) responseAsBytes[iterator]);
                    numOfCharToRead--;
                }
                nextHost.append(dot);
                iterator++;
                curByte = responseAsBytes[iterator];
            }
            nextHost.deleteCharAt(nextHost.length() - 1);
        }

        return nextHost.toString();
    }

    private static byte[] PrepareResponseForClient(byte[] unparsedResponse) {
        int index = startOfFlagsIndex;
        short flagsByte = unparsedResponse[index];
        short newFlagsByte = (short) (flagsByte & 0xfb);
        unparsedResponse[index] = (byte) newFlagsByte;
        flagsByte = unparsedResponse[index + 1];
        newFlagsByte = (short) (flagsByte | 0x80);
        unparsedResponse[index + 1] = (byte) newFlagsByte;
        return unparsedResponse;
    }

    private void returnNxDomainErrorToClient(DatagramPacket queryPacket) throws Exception {
        byte[] query = queryPacket.getData();
        short RCodeByte = query[RcodeIndex];
        RCodeByte = (short) (RCodeByte & 0xf0);
        RCodeByte = (short) (RCodeByte | 0x03);
        query[RcodeIndex] = (byte) RCodeByte;
        short QRBitByte = query[startOfFlagsIndex];
        QRBitByte = (short) (QRBitByte | 0x80);
        query[startOfFlagsIndex] = (byte) QRBitByte;

        byte[] response = PrepareResponseForClient(query);
        server.returnDNSQueryResultToUser(response, queryPacket.getLength());
    }

    private String GetWantedHost(byte[] clientDnsQuery) {
        int QueryStart = headerLength;
        int iterator = 0;
        int curByte = 0;
        StringBuilder wantedHost = new StringBuilder();

        while (QueryStart > 0) {
            curByte = clientDnsQuery[iterator];
            iterator++;
            QueryStart--;
        }

        curByte = clientDnsQuery[iterator];
        while (curByte != 0) {
            int numOfCharToRead = curByte;
            while (numOfCharToRead > 0) {
                iterator++;
                wantedHost.append((char) clientDnsQuery[iterator]);
                numOfCharToRead--;
            }
            wantedHost.append(dot);
            iterator++;
            curByte = clientDnsQuery[iterator];
        }
        wantedHost.deleteCharAt(wantedHost.length() - 1);
        return wantedHost.toString();
    }

    private void ReturnQueryAnswerToClient(DatagramPacket DNSQueryResponse) throws Exception {
        byte[] parsedResponse = PrepareResponseForClient(DNSQueryResponse.getData());
        server.returnDNSQueryResultToUser(parsedResponse, DNSQueryResponse.getLength());
    }
}
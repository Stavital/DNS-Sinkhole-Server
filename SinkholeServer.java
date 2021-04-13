package il.ac.idc.cs.sinkhole;

import il.ac.idc.cs.sinkhole.DNSServer;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.Reader;
import java.util.HashSet;

public class SinkholeServer {
    public static void main(String[] args) {
        DNSServer dnsServer = new DNSServer();
        HashSet<String> forbiddenHosts = new HashSet<String>();

        if (args.length >= 1) {
            File blockList = new File(args[0]);
            try {
                Reader reader = new FileReader(blockList);
                BufferedReader BReader = new BufferedReader(reader);
                String hostName;
                while ((hostName = BReader.readLine()) != null) {
                    forbiddenHosts.add(hostName);
                }

            } catch (Exception e) {
                System.err.println(e);
            }
        }
        dnsServer.DoMainLogic(forbiddenHosts);
    }
}

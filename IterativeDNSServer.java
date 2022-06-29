package il.ac.idc.cs.sinkhole;

import java.io.IOException;
import java.net.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

class IterativeDNSServer {

    private DatagramSocket serverSocket;
    private final RecursiveDNSClient recursiveDNSClient;
    private final int serverSendToPort;
    public static final int DNS_UDP_PACKET_SIZE = 1024;
    List<String> _rootServerHostNames = new ArrayList<>();

    public BlockListEnforcer blockListEnforcer;
    private DatagramPacket requestedPacket;
    private DNSPacketHandler requestDNSPacketHandler;

    public IterativeDNSServer(int listenPort, BlockListEnforcer blockListEnforcer) {
        serverSendToPort = listenPort;
        serverSocket = null;
        this.blockListEnforcer = blockListEnforcer;
        recursiveDNSClient = new RecursiveDNSClient();
        initRootServerHostNames();
    }

    private void initRootServerHostNames() {
        _rootServerHostNames.add("a.root-servers.net");
        _rootServerHostNames.add("b.root-servers.net");
        _rootServerHostNames.add("c.root-servers.net");
        _rootServerHostNames.add("d.root-servers.net");
        _rootServerHostNames.add("e.root-servers.net");
        _rootServerHostNames.add("f.root-servers.net");
        _rootServerHostNames.add("g.root-servers.net");
        _rootServerHostNames.add("h.root-servers.net");
        _rootServerHostNames.add("i.root-servers.net");
        _rootServerHostNames.add("j.root-servers.net");
        _rootServerHostNames.add("k.root-servers.net");
        _rootServerHostNames.add("l.root-servers.net");
        _rootServerHostNames.add("m.root-servers.net");
    }

    /***
     * The DNS server is busy-waiting:
     * 1.   Listening to port 53, harvesting raw packets.
     * 2.   Deciphering them to extract the DNS query.
     * 3.   Check if they can be accessed via the enforcer.
     * 4.   Prepares and sends a Packet response.
     *
     */
    @SuppressWarnings("InfiniteLoopStatement")
    public void Start() {
        initSentToServerSocket();
        while (true) {
            listeningAndReceiving();
            if (isDomainWhiteList(requestedPacket, requestDNSPacketHandler)) continue;
            preparingAndSending();
        }
    }

    private void preparingAndSending() {
        System.out.println("Iterative DNS Server is preparing response.");
        // Initialize root random IP address
        try {
            InetAddress rootServerAddress = getRandomRootServerAddress();
            DNSPacketHandler responseDNSPacketHandler = recursiveDNSClient.getResponsePacket(requestedPacket, rootServerAddress);
            DatagramPacket responseUdpPacket = new DatagramPacket(
                    responseDNSPacketHandler.getData(),
                    responseDNSPacketHandler.getData().length,
                    requestedPacket.getAddress(),
                    requestedPacket.getPort());
            System.out.println("Iterative DNS Server is sending a final answer to a client.");
            sendResponsePacket(responseUdpPacket);
        } catch (UnknownHostException e){
            System.err.printf("Exception occurred when Iterative DNS Server was trying to fetch " +
                    "IP address of root. exception = %s", e);
        }
    }

    private void listeningAndReceiving() {
        System.out.println("Iterative DNS Server is listening for UDP Packets.");
        requestedPacket = getSentPacket();
        System.out.println("Iterative DNS Server has received a UDP Packet from Client.");
        requestDNSPacketHandler = new DNSPacketHandler(requestedPacket);
    }

    private boolean isDomainWhiteList(DatagramPacket requestUdpPacket, DNSPacketHandler requestDNSPacketHandler) {
        // whitelist the dns domain.
        if (!blockListEnforcer.isAllowed(requestDNSPacketHandler.getQDomainName())) {
            modifyAndSendPacket(requestDNSPacketHandler, requestUdpPacket.getAddress(), requestUdpPacket.getPort());
            return true;
        }
        System.out.println("Iterative DNS Server has received a blocklist Domain name.");
        return false;
    }

    private void sendResponsePacket(DatagramPacket responsePacket) {
        try {
            serverSocket.send(responsePacket);
        } catch (IOException e) {
            System.err.printf("Exception occurred in Iterative DNS Server, " +
                    "while trying to send response Packet to Client. Client probably asleep. exception = %s", e);
        }
    }

    InetAddress getRandomRootServerAddress() throws UnknownHostException {
        int randomIndex = new Random().nextInt(_rootServerHostNames.size());
        return InetAddress.getByName(_rootServerHostNames.get(randomIndex));
    }

    /***
     * Rather then building an entirely new packet, we make the necessary adjustments and send the packet.
     * @param packetToModify - The Packet that is to be modified.
     * @param clientAddress
     * @param clientPort
     */
    private void modifyAndSendPacket(DNSPacketHandler packetToModify, InetAddress clientAddress, int clientPort) {
        packetToModify.setRCodeToNXDomain();
        packetToModify.setResponseBit(true);
        packetToModify.setRecursionBit(true);
        DatagramPacket finalResponseToClient = new DatagramPacket(
                packetToModify.getData(),
                packetToModify.getData().length,
                clientAddress,
                clientPort);
        System.out.println("Iterative DNS Server is responding with malformed Domain.");
        sendResponsePacket(finalResponseToClient);
    }

    private DatagramPacket getSentPacket() {
        byte[] receiveData = new byte[DNS_UDP_PACKET_SIZE];
        DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
        try {
            this.serverSocket.receive(receivePacket);
        } catch (IOException e) {
            System.err.printf("Exception occurred in Iterative DNS Server, while trying to receive Packet. " +
                    "Call Google, and switch Server connection to your mobile network. exception = %s", e);
        }
        return receivePacket;
    }

    private void initSentToServerSocket() {
        try {
            this.serverSocket = new DatagramSocket(serverSendToPort);
            System.out.printf("Iterative DNS Server started listening on port %s.\r\n", serverSendToPort);
        } catch (SocketException e) {
            System.err.printf("Exception occurred in Iterative DNS Server, while initializing Server Socket. " +
                    "If you are running an old version of Ubuntu, it will probably take you 25 hours to recognize" +
                    "it. Please be advised. exception = %s", e);
        }
    }
}
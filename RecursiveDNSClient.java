package il.ac.idc.cs.sinkhole;

import java.io.IOException;
import java.net.*;

public class RecursiveDNSClient {

    public static final int DNS_CLIENT_SENT_TO_PORT = 53;
    public static final int DNS_UDP_PACKET_SIZE = 1024;
    private static final int QUERY_ITERS_LIMIT = 16;

    private final byte[] receivedDataSize;
    private DatagramSocket clientSocket;
    private DNSPacketHandler originalDNSQuery;

    public RecursiveDNSClient() {
        receivedDataSize = new byte[DNS_UDP_PACKET_SIZE];
        try {
            clientSocket = new DatagramSocket(DNS_CLIENT_SENT_TO_PORT);
        } catch (SocketException e) {
            System.err.printf("Exception occurred while trying to open UDP socket to Client. exception = %s", e);
        }
    }

    /***
     * We build upon the response from the root server to start challenging our iterative DNS server for a final
     * answer regarding our target domain-name. We also limit ourselves to 16 iterations.
     * There is always translation between received queries and responses, for both communicating sides.
     * @param packetToQuery
     * @param rootAddress
     * @return
     */
    public DNSPacketHandler getResponsePacket(DatagramPacket packetToQuery, InetAddress rootAddress) {
        // Obtaining results from root server
        DatagramPacket rootReceivedPacket = getRootReceivedPacket(packetToQuery, rootAddress);
        DNSPacketHandler lastResponsePacket = new DNSPacketHandler(rootReceivedPacket);
        // Iterating to get response
        int iterationNumber = 1;
        // run on all servers.
        while (!lastResponsePacket.isFinalAnswer() && iterationNumber < QUERY_ITERS_LIMIT) {
            DatagramPacket lastReceivedPacket = challengingDNS(lastResponsePacket);
            lastResponsePacket = new DNSPacketHandler(lastReceivedPacket);
            iterationNumber++;
        }
        // flip necessary bits.
        lastResponsePacket.setRecursionBit(true);
        lastResponsePacket.setAuthAnswerBit(false);
        return lastResponsePacket;
    }

    private DatagramPacket getRootReceivedPacket(DatagramPacket packetToQuery, InetAddress rootAddress) {
        // Prepare packet for root
        originalDNSQuery = new DNSPacketHandler(packetToQuery);
        DatagramPacket packetForRoot = new DatagramPacket(
                originalDNSQuery.getData(),
                originalDNSQuery.getData().length,
                rootAddress,
                DNS_CLIENT_SENT_TO_PORT);
        sendQueryPacket(packetForRoot);
        return getSentPacket();
    }

    private DatagramPacket challengingDNS(DNSPacketHandler lastResponsePacket) {
        // Prepare new Packet
        DatagramPacket packetForNextDNS = null;
        try {
            packetForNextDNS = new DatagramPacket(
                    originalDNSQuery.getData(),
                    originalDNSQuery.getData().length,
                    InetAddress.getByName(lastResponsePacket.getAuthority()),
                    DNS_CLIENT_SENT_TO_PORT);
        } catch (UnknownHostException e) {
            System.err.printf("Unknown host exception occurred when retrieving the auth server IP. exception = %s", e);
        }
        // Send to DNS and get response
        sendQueryPacket(packetForNextDNS);
        return getSentPacket();
    }

    private void sendQueryPacket(DatagramPacket responsePacket) {
        try {
            System.out.println("Recursive DNS Client is sending datagram to authority (or root) DNS server.");
            clientSocket.send(responsePacket);
        } catch (IOException e) {
            System.err.printf("Exception occurred while Recursive DNS Client was trying to send " +
                    "query Packet to DNS server. exception = %s", e);
        }
    }

    private DatagramPacket getSentPacket() {
        DatagramPacket receivedPacket = new DatagramPacket(receivedDataSize, receivedDataSize.length);
        try {
            System.out.println("Recursive DNS Client is waiting for Authority DNS server to respond.");
            this.clientSocket.receive(receivedPacket);
            System.out.println("Recursive DNS Client received response " +
                    "from DNS Authority server: " + receivedPacket.getAddress().toString());
        } catch (IOException e) {
            System.err.printf("Exception occurred while Recursive DNS Client was trying to receive " +
                    "Packet from an Authority DNS server. exception = %s", e);
        }
        return receivedPacket;
    }

}

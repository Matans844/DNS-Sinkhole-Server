package il.ac.idc.cs.sinkhole;

import java.net.DatagramPacket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class DNSPacketHandler {

    private static final int THRESHOLD_TO_READING_PTR = 192;
    private static final int BYTE_COUNT = 8;
    public static final int LENGTH_OF_HEADER = 12;
    public static final short SIZE_OF_CRR_TYPE = 2;
    public static final short SIZE_OF_CRRC_CLASS = 2;
    public static final short SIZE_OF_CRR_TTL = 4;
    public static final short SIZE_OF_CRD_LENGTH = 2;
    public static final short INDEX_OF_CQR_FLAG_BYTE = 2;
    public static final short INDEX_OF_CR_CODE_BYTE = 3;
    public static final short INDEX_OF_ANS_CNT_BYTE = 6;
    public static final short INDEX_OF_CNs_CNT_BYTE = 8;
    private final int ANSWER_CNT;
    private final int AUTH_CNT;
    private final int RESPONSE_CODE;
    private final String primaryAuthServerName;
    private final String queriedName;
    private byte[] rawDNSData;
    private int packetIndex;

    /***
     * Here we begin processing a captured packet to extract its DNS contents
     * @param packetFromUDP
     */
    public DNSPacketHandler(DatagramPacket packetFromUDP) {
        rawDNSData = packetFromUDP.getData();
        ANSWER_CNT = extractInfoFromIndices(INDEX_OF_ANS_CNT_BYTE);
        AUTH_CNT = extractInfoFromIndices(INDEX_OF_CNs_CNT_BYTE);
        RESPONSE_CODE = rawDNSData[INDEX_OF_CR_CODE_BYTE] & 15;
        packetIndex = LENGTH_OF_HEADER;
        queriedName = extractServerName();
        // Skip packet segments
        packetIndex += SIZE_OF_CRR_TYPE + SIZE_OF_CRRC_CLASS;
        if (ANSWER_CNT != 0) skipAnswerSection();
        primaryAuthServerName = (AUTH_CNT == 0) ? null : getFirstAuthServer();
        // remove additional RRs.
        rawDNSData = Arrays.copyOfRange(rawDNSData, 0, packetIndex);
        // set the two bytes of additional records to zero.
        rawDNSData[10] = 0;
        rawDNSData[11] = 0;
    }

    /***
     * Using standard indices, we can help move around the packet
     * @param infoIndex
     * @return
     */
    private int extractInfoFromIndices(short infoIndex) {
        return (rawDNSData[infoIndex] << BYTE_COUNT) + rawDNSData[infoIndex + 1];
    }

    public byte[] getData() {
        return rawDNSData;
    }

    public String getQDomainName() {
        return queriedName;
    }

    public void setResponseBit(boolean hasResponse) {
        byte positiveBit = (byte) ((ByteToUnsignedInt(rawDNSData[INDEX_OF_CQR_FLAG_BYTE]) & 127) + 128);
        byte negativeBit = (byte) (ByteToUnsignedInt(rawDNSData[INDEX_OF_CQR_FLAG_BYTE]) & 127);
        rawDNSData[INDEX_OF_CQR_FLAG_BYTE] = (hasResponse) ? positiveBit : negativeBit;
    }

    public void setRecursionBit(boolean hasRecursion) {
        byte positiveBit = (byte) ((ByteToUnsignedInt(rawDNSData[INDEX_OF_CR_CODE_BYTE]) & 127) + 128);
        byte negativeBit = (byte) (ByteToUnsignedInt(rawDNSData[INDEX_OF_CR_CODE_BYTE]) & 127);
        rawDNSData[INDEX_OF_CR_CODE_BYTE] = (hasRecursion) ? positiveBit : negativeBit;
    }

    public void setAuthAnswerBit(boolean isAuth) {
        byte positiveBit = (byte) ((ByteToUnsignedInt(rawDNSData[INDEX_OF_CQR_FLAG_BYTE]) & 251) + 4);
        byte negativeBit = (byte) (ByteToUnsignedInt(rawDNSData[INDEX_OF_CQR_FLAG_BYTE]) & 251);
        rawDNSData[INDEX_OF_CQR_FLAG_BYTE] = (isAuth) ? positiveBit : negativeBit;
    }

    public void setRCodeToNXDomain() {
        rawDNSData[INDEX_OF_CR_CODE_BYTE] =
                (byte) ((ByteToUnsignedInt(rawDNSData[INDEX_OF_CR_CODE_BYTE]) & 240) + 3);
    }

    public boolean isFinalAnswer() {
        boolean isQuery = (rawDNSData[INDEX_OF_CQR_FLAG_BYTE] & 128) == 0;
        return (ANSWER_CNT > 0 || RESPONSE_CODE != 0 || primaryAuthServerName == null) & !isQuery;
    }

    public String getAuthority() {
        return primaryAuthServerName;
    }

    private String getFirstAuthServer() {
        List<String> authorityNames = new ArrayList<>();
        int iterRDataLength;
        int iterPosBefRData;
        // Loop to get Authorities
        for (int i = 0; i < AUTH_CNT; i++) {
            // Move past hosts and flags.
            extractServerName();
            packetIndex += SIZE_OF_CRR_TYPE + SIZE_OF_CRRC_CLASS + SIZE_OF_CRR_TTL;
            // Identify segment edge indices.
            iterRDataLength = (rawDNSData[packetIndex] << BYTE_COUNT) | rawDNSData[packetIndex + 1];
            packetIndex += SIZE_OF_CRD_LENGTH;
            iterPosBefRData = packetIndex;
            // Extract authority.
            authorityNames.add(extractServerName());
            // Update index to next iteration
            packetIndex = iterPosBefRData + iterRDataLength;
        }
        return authorityNames.get(0);
    }

    private void skipAnswerSection() {
        for (int i = 0; i < ANSWER_CNT; i++) {
            // Skip names and TYPE,CLASS,TTL
            int current = ByteToUnsignedInt(rawDNSData[packetIndex]);
            while (current != 0 && current < THRESHOLD_TO_READING_PTR) {
                packetIndex++;
                current = ByteToUnsignedInt(rawDNSData[packetIndex]);
            }
            packetIndex = (current != 0) ? packetIndex += 2 : packetIndex++;
            packetIndex += SIZE_OF_CRR_TYPE + SIZE_OF_CRRC_CLASS + SIZE_OF_CRR_TTL;
            // Move past RDLENGTH
            int rdLength = (rawDNSData[packetIndex] << BYTE_COUNT) + rawDNSData[packetIndex + 1];
            packetIndex += rdLength + 2;
        }
    }

    /***
     * This loops traverses a packet through sections, gathering labels
     * @return The Domain Name that lies inside the packet
     */
    private String extractServerName() {
        // Data structures for name extraction
        List<Character> nameLabelsRead = new ArrayList<>();
        StringBuilder domainName = new StringBuilder();
        // Preparing to navigate between sections and in labels
        int byteIndex = packetIndex;
        boolean didPtrJump = false;
        boolean notContent = true;
        int labelContentLength = 0;
        int labelContentByte = 1;
        int currentIndex = ByteToUnsignedInt(rawDNSData[byteIndex]);
        // Loop according to section and label
        while (currentIndex != 0) {
            if (currentIndex >= THRESHOLD_TO_READING_PTR) {
                byteIndex = ((currentIndex - THRESHOLD_TO_READING_PTR) << BYTE_COUNT) + rawDNSData[byteIndex + 1];
                notContent = true;
                didPtrJump = true;
            } else {
                // Check if we reached required content.
                if (notContent) {
                    labelContentLength = currentIndex;
                    notContent = false;
                } else {
                    // Check if we reached last content label byte.
                    if (labelContentByte == labelContentLength) {
                        notContent = true;
                        labelContentByte = 1;
                        nameLabelsRead.add((char) currentIndex);
                        // Completed current label.
                        // Append and make room for new labels.
                        appendLabelToServername(domainName, nameLabelsRead);
                        nameLabelsRead.clear();
                    } else {
                        labelContentByte++;
                        nameLabelsRead.add((char) currentIndex);
                    }
                }
                byteIndex++;
                if (!didPtrJump) packetIndex++;
            }
            currentIndex = ByteToUnsignedInt(rawDNSData[byteIndex]);
        }
        // Update index according to label length or jump to the next section
        int update = (didPtrJump) ? 2 : 1;
        packetIndex += update;
        // Trim closing period and return name
        domainName.deleteCharAt(domainName.length() - 1);
        return domainName.toString();
    }

    private static void appendLabelToServername(StringBuilder domainName, List<Character> nameLabelsRead) {
        for (char c : nameLabelsRead) {
            domainName.append(c);
        }
        domainName.append('.');
    }

    private int ByteToUnsignedInt(byte byteToCast) {
        return (int) byteToCast & 0xff;
    }
}
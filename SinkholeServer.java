package il.ac.idc.cs.sinkhole;

import java.util.HashSet;

/***
 * We differentiate between receiving a block-list flag, and not.
 * If we do receive an input, we use a HashSet to determine which DNS records are to be blocked.
 */
public class SinkholeServer {

    public static final int DNS_SERVER_SENT_TO_PORT = 5300;

    public static void main(String[] args) {
        BlockListForDNS blockListLoader = new BlockListForDNS();
        String blockListFilePath;
        HashSet<String> blockList = new HashSet<>();

        if (args.length != 0) {
            blockListFilePath = args[0];
            blockList = blockListLoader.Load(blockListFilePath);
        }
        BlockListEnforcer blockListEnforcer = new BlockListEnforcer(blockList);

        IterativeDNSServer server = new IterativeDNSServer(DNS_SERVER_SENT_TO_PORT, blockListEnforcer);
        server.Start();
    }
}

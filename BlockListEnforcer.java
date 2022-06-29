package il.ac.idc.cs.sinkhole;

import java.util.HashSet;

/**
 * This class allows us to supply the Server object with a HashSet which can help it make
 * decisions regarding blocked DNS records
 */
public class BlockListEnforcer {

    private final HashSet<String> blockListEnforcer;

    public BlockListEnforcer(HashSet<String> enforceList){
        this.blockListEnforcer = enforceList;
    }

    public boolean isAllowed(String domain)
    {
        return !blockListEnforcer.contains(domain);
    }

}

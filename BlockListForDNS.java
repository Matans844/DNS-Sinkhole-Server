package il.ac.idc.cs.sinkhole;

import java.io.*;
import java.util.HashSet;

public class BlockListForDNS {

    public BlockListForDNS() {
    }

    public HashSet<String> Load(String filePath) {
        // Establish reader.
        System.out.println("Recursive DNS Client is loading DNS blocklist.");
        BufferedReader reader = getBlockListFileReader(filePath);
        return (reader == null) ? new HashSet<>() : getHashSet(reader);
    }

    private BufferedReader getBlockListFileReader(String filePath) {
        BufferedReader reader = null;
        try {
            File file = new File(filePath);
            reader = new BufferedReader(new FileReader(file));
        } catch (FileNotFoundException e) {
            System.err.printf("Exception occurred in BlockListForDNS " +
                    "while establishing reader. exception = %s \r\n", e);
        }
        return reader;
    }

    private HashSet<String> getHashSet(BufferedReader reader) {
        HashSet<String> blockList = new HashSet<>();
        String line;
        try {
            while ((line = reader.readLine()) != null) {
                if (line.isEmpty()) {
                    break;
                }
                blockList.add(line);
            }
        } catch (IOException e) {
            System.err.printf("Exception occurred in BlockListForDNS " +
                    "while reading file. exception = %s", e);
        }
        return blockList;
    }
}

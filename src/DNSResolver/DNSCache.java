package DNSResolver;

import java.util.HashMap;

// Local Cache of DNSRecords
public class DNSCache {
    private static HashMap<DNSQuestion, DNSRecord> cache;

    public DNSCache() {
        cache = new HashMap<>();
    }

    public static boolean contains (DNSQuestion question) {
        if (cache.containsKey(question)) {
            if(cache.get(question).timestampValid()) {
                return true;
            } else {
                cache.remove(question);
            }
        }
        return false;
    }

    public static DNSRecord getRecord(DNSQuestion question) {
        return cache.get(question);
    }

    static void addRecord(DNSQuestion question, DNSRecord record) {
        cache.put(question, record);
    }

}

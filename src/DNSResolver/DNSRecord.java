package DNSResolver;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;

// DNS Records contain the needed to respond to a DNS Question
// These have a Time To Live built in, as records can update
// Records are created from Google Responses and Stored in the Cache
// Records past TTL need to be requested from Google again
// Details about components of a record come from:
// https://www.ietf.org/rfc/rfc1035.txt and https://www.zytrax.com/books/dns/ch15/#answer
public class DNSRecord {
    // Name of the record
    private String[] name;

    // 16 bit indicator per DNS protocol
    private int type;

    // 16 bit indicator, only uses 1 for Internet for this assignment
    private int rClass;

    // 32 bit indicator, time in seconds a record is valid
    private int ttl;

    // how many bytes the data the record contains
    private int rLength;

    // The record data
    private byte[] rData;

    // Time the record will no longer be valid, based in TTL
    // This is not sent or received, but calculated and stored when record is created
    private Calendar deathTime;

    public void setName(String[] name) {
        this.name = name;
    }

    public static DNSRecord decodeRecord(ByteArrayInputStream input, DNSMessage message){
        DNSRecord record = new DNSRecord();
        record.name = message.readDomainName(input);
        record.type = DNSMessage.getByteGroup(2, input);
        record.rClass = DNSMessage.getByteGroup(2, input);
        record.ttl = DNSMessage.getByteGroup(4, input);
        record.rLength = DNSMessage.getByteGroup(2, input);
        record.rData = new byte[record.rLength];
        for (int i = 0; i < record.rLength; i++) {
            record.rData[i] = (byte) input.read();
        }
        record.deathTime = Calendar.getInstance();
        record.deathTime.add(Calendar.SECOND, record.ttl);

        return record;
    }

    public void writeBytes(ByteArrayOutputStream output, HashMap<String, Integer> domainNameLocations) throws IOException {
        DNSMessage.writeDomainName(output, domainNameLocations, name);
        writeAnswer(2, output, type);
        writeAnswer(2, output, rClass);
        writeAnswer(4, output, ttl);
        writeAnswer(2, output, rLength);
        for (byte b : rData) {
            output.write(b);
        }
    }

    // Return whether the creation date + the time to live is after the current time.
    // The Date and Calendar classes will be useful for this.
    public boolean timestampValid(){
        Calendar currentTime = Calendar.getInstance();
        return currentTime.before(deathTime);
    }

    // Return a human readable string version of a record object.
    // IDE Generated
    @Override
    public String toString() {
        return "DNSRecord{" + "name=" + Arrays.toString(name) + ", type=" + type +
                ", rClass=" + rClass + ", ttl=" + ttl + ", rLength=" + rLength +
                ", rData=" + Arrays.toString(rData) + '}';
    }

    // Helper for outputting correct answer fields
    public static void writeAnswer(int numberBytes, ByteArrayOutputStream output, int input) {
        byte temp[] = new byte[numberBytes];
        for (int i = numberBytes - 1; i >= 0; i--) {
            temp[i] = (byte) input;
            input >>= 8;
        }
        for (byte b : temp) {
            output.write(b);
        }
    }
}

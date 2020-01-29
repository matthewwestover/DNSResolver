package DNSResolver;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Objects;

// This creates the "Question" section of a DNS Message.
// This stays constant in requests and responses, does not need to be edited once created.
// Details about question components found from:
// https://www.ietf.org/rfc/rfc1035.txt and https://www.zytrax.com/books/dns/ch15/#question
public class DNSQuestion {
    // qName is the domain name being requested
    private String[] qName;

    //qType is the resource records being requested
    private int qType;

    // qClass is the Resource Record(s) class being requested, for instance, internet, chaos etc.
    // internet for the purposes of our assignment = 1
    private int qClass;

    // Getter for question name
    public String[] getqName() {
        return qName;
    }

    // Return a human readable string version of a question object.
    // IDE Generated
    @Override
    public String toString() {
        return "DNSQuestion{" + "qName=" + Arrays.toString(qName) +
                ", qType=" + qType + ", qClass=" + qClass + '}';
    }

    // Compares two questions
    // IDE Generated
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DNSQuestion that = (DNSQuestion) o;
        return qType == that.qType &&
                qClass == that.qClass &&
                Arrays.equals(qName, that.qName);
    }

    // Creates a hashCode
    // IDE Generated
    @Override
    public int hashCode() {
        int result = Objects.hash(qType, qClass);
        result = 31 * result + Arrays.hashCode(qName);
        return result;
    }

    // Read a question from the input stream. Due to compression,
    public static DNSQuestion decodeQuestion(ByteArrayInputStream input , DNSMessage message){
        DNSQuestion question = new DNSQuestion();
        question.qName = message.readDomainName(input);
        question.qType = DNSMessage.getByteGroup(2, input);
        question.qClass = DNSMessage.getByteGroup(2, input);
        return question;
    }

    // Write the question bytes which will be sent to the client
    // The hash map is used for us to compress the message
    void writeBytes(ByteArrayOutputStream output, HashMap<String,Integer> domainNameLocations) throws IOException {
        DNSMessage.writeDomainName(output, domainNameLocations, qName);
        output.write(DNSMessage.intToByteArray(qType));
        output.write(DNSMessage.intToByteArray(qClass));
    }

}
package DNSResolver;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

public class DNSMessage {
    private byte[] rawData;
    private DNSHeader header = new DNSHeader();
    private DNSQuestion[] questions;
    private DNSRecord[] answers;
    private DNSRecord[] nsRecords;
    private DNSRecord[] additionalRecords;

    //Getters for Data
    public byte[] getRawData() {
        return rawData;
    }
    public DNSHeader getHeader() {
        return header;
    }
    public DNSQuestion[] getQuestions(){
        return questions;
    }
    public DNSRecord[] getAnswers() {
        return answers;
    }
    public DNSRecord[] getNSRecords() {
        return nsRecords;
    }
    public DNSRecord[] getAddRecords() {
        return additionalRecords;
    }

    // Helper Methods for reading and writing bits/bytes
    // Pulls out specified number of Bytes (8 bits each)
    public static int getByteGroup(int numBytes, ByteArrayInputStream input) {
        int result = 0;
        int mask = 0xff;
        for (int i = numBytes - 1; i >= 0; i--){ // i is used to shift bits, needs to be 0 on last loop for no shifting
            int tempByte = input.read();
            tempByte = tempByte & mask;
            tempByte = tempByte << (8 * i);
            result = result | tempByte;
        }

        return result;
    }

    // Pulls out single bit for use
    public static int getSingleBit(int inputByte, int bitLocation) {
        int result = 0;
        int mask = 0xff;
        int temp = 0;
        temp = inputByte << bitLocation;
        result = result | temp;
        result = result & mask;
        result = result >> 7;

        return result;
    }

    // Converts 16 bit ints to byte[]
    public static byte [] intToByteArray(int n) {
        byte [] bytes = new byte [2];
        bytes[0] = (byte) (n >> 8 & 0xff);
        bytes[1] = (byte) (n & 0xff);
        return bytes;
    }

    public static DNSMessage decodeMessage(byte[] bytes) throws IOException {
        DNSMessage message = new DNSMessage();

        message.rawData = bytes;
        ByteArrayInputStream input = new ByteArrayInputStream(bytes);
        message.header = DNSHeader.decodeHeader(input);
        message.questions = new DNSQuestion[message.header.getQdCount()];
        for (int i = 0; i < message.questions.length; i++) {
            message.questions[i] = DNSQuestion.decodeQuestion(input, message);
        }
        message.answers = new DNSRecord[message.header.getAnCount()];
        for (int i = 0; i < message.answers.length; i++) {
            message.answers[i] = DNSRecord.decodeRecord(input, message);
        }
        message.nsRecords = new DNSRecord[message.header.getNsCount()];
        for (int i = 0; i < message.nsRecords.length; i++) {
            message.nsRecords[i] = DNSRecord.decodeRecord(input, message);
        }
        message.additionalRecords = new DNSRecord[message.header.getArCount()];
        for (int i = 0; i < message.additionalRecords.length; i++) {
            message.additionalRecords[i] = DNSRecord.decodeRecord(input, message);
        }

        return message;
    }

    // Read the pieces of a domain name starting from the current position of the input stream
    public String[] readDomainName(ByteArrayInputStream input){
        ArrayList<String> sections = new ArrayList<>();
        while (true) {
            byte length = (byte) input.read();
            if (length < 0) {
                int mask = 0x3F;
                length = (byte) (length & mask);
                length = (byte) (length << 8);
                length = (byte) (length | input.read());
                return readDomainName(length);
            }
            if (length == 0) {
                break;
            }
            String section = "";
            for (int i = 0; i < length; i++) {
                section += (char) input.read();
            }
            sections.add(section);
        }
        String[] domain = new String[sections.size()];
        for (int i = 0; i < domain.length; i++) {
            domain[i] = sections.get(i);
        }
        return domain;
    }

    // Same, but used when there's compression and we need to find the domain from earlier in the message.
    // This method should make a ByteArrayInputStream that starts at the specified byte and call the other version of this method
    public String[] readDomainName(int firstByte){
        ByteArrayInputStream input = new ByteArrayInputStream(rawData);
        input.skip(firstByte);
        return readDomainName(input);
    }

    // Build a response based on the request and the answers you intend to send back.
    public static DNSMessage buildResponse(DNSMessage request, DNSRecord[] answers){
        DNSMessage response = new DNSMessage();
        response.questions = request.getQuestions();
        response.answers = answers;
        response.nsRecords = request.getNSRecords();
        response.additionalRecords = request.getAddRecords();
        response.header = DNSHeader.buildResponseHeader(request, response);
        return response;
    }

    // Get the bytes to put in a packet and send back.
    public byte[] toBytes() throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        HashMap<String, Integer> dnLocations = new HashMap<>();
        header.writeBytes(output);
        for (DNSQuestion question : questions) {
            question.writeBytes(output, dnLocations);
        }
        for (DNSRecord record : answers) {
            record.writeBytes(output, dnLocations);
        }
        for (DNSRecord record : nsRecords) {
            record.writeBytes(output, dnLocations);
        }
        for (DNSRecord record : additionalRecords) {
            record.writeBytes(output, dnLocations);
        }

        return output.toByteArray();
    }

    // If this is the first time we've seen this domain name in the packet,
    // write it using the DNS encoding (each segment of the domain prefixed with its length,
    // 0 at the end), and add it to the hash map. Otherwise, write a back pointer to where the domain has been seen previously.
    public static void writeDomainName(ByteArrayOutputStream output, HashMap<String,Integer> domainLocations, String[] domainPieces){
        String fullDomain = octetsToString(domainPieces);
        if (domainLocations.containsKey(fullDomain)) {
            int pointer = domainLocations.get(fullDomain);
            byte secondByte = (byte) pointer;
            pointer = pointer >> 8;
            byte firstByte = (byte) pointer;
            byte mask = (byte) 0xC0;
            firstByte = (byte) (firstByte | mask);
            output.write(firstByte);
            output.write(secondByte);
        } else {
            domainLocations.put(fullDomain, output.size());
            for (int i = 0; i < domainPieces.length; i++) {
                output.write(domainPieces[i].length());
                for (char c : domainPieces[i].toCharArray()) {
                    output.write(c);
                }
            }
            output.write(0);
        }
    }

    // Join the pieces of a domain name with dots ([ "utah", "edu"] -> "utah.edu" )
    public static String octetsToString(String[] octets) {
        String result = "";
        for(int i = 0; i < octets.length; i++) {
            result += octets[i];
            if (i < octets.length - 1) {
                result += ".";
            }
        }
        return result;
    }

    // Return a human readable string version of a message object.
    // IDE Generated
    @Override
    public String toString() {
        return "DNSMessage{" +
                "header=" + header + ", questions=" + Arrays.toString(questions) +
                ", answers=" + Arrays.toString(answers) + ", nsRecords=" + Arrays.toString(nsRecords) +
                ", additionalRecords=" + Arrays.toString(additionalRecords) + '}';
    }

}

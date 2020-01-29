package DNSResolver;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

// This class stores the info from the first 12 bytes of an incoming DNS Request
// Details as to what bits do what was obtained from:
// https://www.ietf.org/rfc/rfc1035.txt and https://www.zytrax.com/books/dns/ch15/#opcode
public class DNSHeader {
    // Message ID - 16 bits (2 bytes)
    // Created by requesting client, returned unchanged by the server
    private int id;

    // QR Code - 1 bit
    // 0 = Query
    // 1 = Response
    private int qr;

    // opCode - 4 bits
    // 0 = Query
    // 1 = IQuery (inverse query)
    // 2 = Status
    private int opCode;

    // Authoritative Answer (AA) - 1 Bit
    // Valid in responses only
    private int aa;

    // Truncation (TC) - 1 bit
    // Message is truncated, on until last message is sent
    private int tc;

    // Recursion Desired (RD)- 1 bit
    // If valid, pursues the request recursively. Optional support
    private int rd;

    // Recursion Available (RA) - 1 bit
    // If server allows recursive queries this bit is on in the response
    private int ra;

    // Z - 3 bits
    // Reserved space for future use. 0s in all bits
    private int z;

    // Response Code (rCode) - 4 bits
    // 0 = No Error
    // 1 = Format Error
    // 2 = Server Failure
    // 3 = Name Error
    // 4 = Not Implemented
    // 5 = Refused
    private int rCode;

    // QDCount - 16 bit int
    // Total questions provided in question section
    private int qdCount;

    // ANCount - 16 bit int
    // Total answers provided in the answer section
    private int anCount;

    // NSCount - 16 bit int
    // Total name servers provided in the authority section
    private int nsCount;

    // ARCount - 16 bit int
    // Total additional resources in the additional section
    private int arCount;

    // Getters for Data
    public int getId() {
        return id;
    }
    public int getQdCount() {
        return qdCount;
    }
    public int getAnCount() {
        return anCount;
    }
    public int getNsCount() {
        return nsCount;
    }
    public int getArCount() {
        return arCount;
    }

    // Read header bites from input stream with ByteArrayInputStream
    public static DNSHeader decodeHeader(ByteArrayInputStream input) throws IOException {
        DNSHeader header = new DNSHeader();
        int mask = 0xf;
        // Pull out first two bytes for the ID
        header.id = DNSMessage.getByteGroup(2, input);

        // Third Byte contains a single bit, followed by a 4 bits opcode, followed by 3 single bit fields
        int byteThree = DNSMessage.getByteGroup(1, input);
        header.qr = DNSMessage.getSingleBit(byteThree, 0);
        header.aa = DNSMessage.getSingleBit(byteThree, 5);
        header.tc = DNSMessage.getSingleBit(byteThree, 6);
        header.rd = DNSMessage.getSingleBit(byteThree, 7);
        byteThree = byteThree >> 3; //remove last bits to get opCode
        header.opCode = byteThree & mask;

        // Fourth Byte contains single bit, 3 bits for the "z" space, 4 bits for the rCode
        int byteFour = DNSMessage.getByteGroup(1, input);
        header.ra = DNSMessage.getSingleBit(byteFour, 0);
        header.z = DNSMessage.getSingleBit(byteFour, 1);
        header.z = header.z << 1;
        header.z = header.z & DNSMessage.getSingleBit(byteFour, 2);
        header.z = header.z << 1;
        header.z = header.z & DNSMessage.getSingleBit(byteFour, 3);
        header.z = header.z & mask;
        header.rCode = header.rCode | byteFour;
        header.rCode = header.rCode & mask;

        // Remaining header fields are 2 bytes each
        header.qdCount = DNSMessage.getByteGroup(2, input);
        header.anCount = DNSMessage.getByteGroup(2, input);
        header.nsCount = DNSMessage.getByteGroup(2, input);
        header.arCount = DNSMessage.getByteGroup(2, input);

        return header;
    }

    // Generate a Response Header object for sending back to client
    public static DNSHeader buildResponseHeader(DNSMessage request, DNSMessage response) {
        DNSHeader responseHeader = new DNSHeader();
        responseHeader.id = request.getHeader().getId();
        responseHeader.qr = 1;
        responseHeader.opCode = 0;
        responseHeader.aa = 0;
        responseHeader.tc = 0;
        responseHeader.rd = 1;
        responseHeader.ra = 1;
        responseHeader.z = 0;
        responseHeader.rCode = 0;
        responseHeader.qdCount = response.getQuestions().length;
        responseHeader.anCount = response.getAnswers().length;
        responseHeader.nsCount = response.getNSRecords().length;
        responseHeader.arCount = response.getAddRecords().length;

        return responseHeader;
    }

    // Encode the header to bytes to be sent back to the client.
    void writeBytes(ByteArrayOutputStream output) throws IOException {
        output.write(DNSMessage.intToByteArray(id));
        // QR|OPCODE|AA|TC|RD|RA|Z|RCODE = 16 bits
        // 1|0000|0|0|1|1|000|0000 = 1000000110000000 = 33152 = 0x8180
        output.write(DNSMessage.intToByteArray(33152));
        output.write(DNSMessage.intToByteArray(qdCount));
        output.write(DNSMessage.intToByteArray(anCount));
        output.write(DNSMessage.intToByteArray(nsCount));
        output.write(DNSMessage.intToByteArray(arCount));
    }

    // Return a human readable string version of a header object.
    // IDE Generated
    @Override
    public String toString() {
        return "DNSHeader{" + "id=" + id + ", qr=" + qr + ", opCode=" + opCode + ", aa=" + aa +
                ", tc=" + tc + ", rd=" + rd + ", ra=" + ra + ", z=" + z + ", rCode=" + rCode +
                ", qdCount=" + qdCount + ", anCount=" + anCount + ", nsCount=" + nsCount +
                ", arCount=" + arCount + '}';
    }
}

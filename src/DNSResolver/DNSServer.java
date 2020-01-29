package DNSResolver;

import java.io.IOException;
import java.net.*;
import java.util.ArrayList;


// A DNS Server opens a UDP socket (DatagramSocket) and listens for incoming DNS requests
// It will evaluate the DNS question in the request, and compare it to the stored answers in the DNS Cache
// If an answer matches, and its time to live (TTL) is still valid, it will generate the reply and return to requestor
// If no answer matches, it forwards the request to Google at 8.8.8.8
// Google's response is parsed and stored as a DNS Answer inside the server cache, and the reply is generated using that
// Use 'dig url.com @127.0.0.1 -p 8053' to send a DNS request for specific URLS
// Data can also be seen via Wireshark - filter 'udp.port == 8053 || udp.port == 53'

public class DNSServer {
    private DatagramSocket clientSocket;
    private DatagramSocket googleSocket;
    private DNSCache cache;
    private boolean isRunning = true;
    private int clientPort = 8053;
    private int googlePort = 53;

    // Server Constructor
    public DNSServer() throws SocketException {
        clientSocket = new DatagramSocket(clientPort);
        googleSocket = new DatagramSocket(googlePort);
        cache = new DNSCache();
    }

    // Server running driver
    public void run() {
        while (isRunning) {
            byte[] buffer = new byte[512];
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            ArrayList<DNSRecord> outputAnswers = new ArrayList<>();
            try {
                clientSocket.receive(packet);
                DNSMessage message = DNSMessage.decodeMessage(buffer);
                System.out.println("Received DNS Request");
                for (DNSQuestion question : message.getQuestions()) {
                    System.out.println("Client port: " + packet.getPort() +" requesting: " + DNSMessage.octetsToString(question.getqName()));
                    if(cache.contains(question)) {
                        System.out.println("Answer found in cache");
                        DNSRecord answer = cache.getRecord(question);
                        outputAnswers.add(answer);
                    } else {
                        System.out.println("Answer NOT found in cache");
                        sendToGoogle(message);
                        System.out.println("Waiting for Google...");
                        byte[] googleBuffer = new byte[512];
                        DatagramPacket googlePacket = new DatagramPacket(googleBuffer, googleBuffer.length);
                        googleSocket.receive(googlePacket);
                        DNSMessage googleMessage = DNSMessage.decodeMessage(googleBuffer);
                        System.out.println("Response Received, adding to cache");
                        if(googleMessage.getAnswers().length != 0) {
                            cache.addRecord(question, googleMessage.getAnswers()[0]);
                            outputAnswers.add(googleMessage.getAnswers()[0]);
                        }
                    }
                }
                DNSMessage response = DNSMessage.buildResponse(message, outputAnswers.toArray(new DNSRecord[outputAnswers.size()]));
                byte[] responseBytes = response.toBytes();
                System.out.println("Sending response to client at port: " + packet.getPort());
                sendToClient(responseBytes, packet);
                System.out.println(message.toString());
                System.out.println(response.toString());

            } catch (IOException e) {
                System.out.println("IO Exception: " + e.getMessage());
                e.printStackTrace();
            }
        }
        clientSocket.close();
    }

    private void sendToGoogle(DNSMessage message) throws UnknownHostException, IOException {
        InetAddress google = InetAddress.getByName("8.8.8.8");
        DatagramPacket output = new DatagramPacket(message.getRawData(), message.getRawData().length, google, googlePort);
        googleSocket.send(output);
    }

    private void sendToClient(byte[] responseBytes, DatagramPacket packet) throws IOException {
        DatagramPacket output = new DatagramPacket(responseBytes, responseBytes.length, packet.getAddress(), packet.getPort());
        clientSocket.send(output);
    }

    // Main Server Runner
    public static void main(String[] args) throws IOException {
        DNSServer server = new DNSServer();
        System.out.println("DNS Server is running on Port " + server.clientPort);
        System.out.println("Listening for DNS requests...");
        server.run();
    }
}
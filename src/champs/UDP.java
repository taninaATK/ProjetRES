package champs;

public class UDP implements Champs {
	private String srcPort;
	private String destPort;
	private String length;
	private String[] checksum;

	public UDP(String src, String dest, String l, String[] check) {
		srcPort = src;
		destPort = dest;
		length = l;
		checksum = check;
	}
	
	public int getSrcPort() {
		return Integer.parseInt(srcPort, 16);
	}
	
	public int getDestPort() {
		return Integer.parseInt(destPort, 16);
	}
	
	public int getLength() {
		return Integer.parseInt(length, 16);
	}
	
	public String getChecksum() {
		return TraceAnalyzer.TraceManager.toString(checksum);
	}
	
	public String analyze() {
		StringBuilder output = new StringBuilder("User Datagram Protocol (UDP) \n");
		output.append("\tSource Port : " + getSrcPort() + "\n");
		output.append("\tDestination Port : " + getDestPort() + "\n");
		output.append("\tLength : " + getLength() + "\n");
		output.append("\tChecksum : 0x" + getChecksum() + "\n");
		return output.append("\n\n").toString();
	}

}

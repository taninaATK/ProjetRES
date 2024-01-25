package champs;

public class ARP implements Champs{
	private String[] hardware;
	private String[] protocol;
	private String[] hlen;
	private String[] plen;
	private String[] operation;
	private String[] senderHA;
	private String[] senderIA;
	private String[] targetHA;
	private String[] targetIA;

	public ARP(String[] h, String[] p, String[] hlen, String[] plen, String[] op, String[] sha, String[] sia,
			String[] tha, String[] tia){
		hardware = h;
		protocol = p;
		this.hlen = hlen;
		this.plen = plen;
		this.operation = op;
		senderHA = sha;
		senderIA = sia;
		targetHA = tha;
		targetIA = tia;
		
	}
	
	public String getHardware() {
		StringBuilder output = new StringBuilder();
		for(String s : hardware) {
			output.append(s);
		}
		int i = Integer.parseInt(output.toString(), 16);
		output = new StringBuilder("Hardware type : ");
		if(i == 2){
			output.append("Experimental Ethernet (2)");
		} else  { 
			output.append("Ethernet (1)");
		}
		
		//System.out.println(output.toString());
		
		return output.toString();
	}

	public String getProtocol() {
		StringBuilder output = new StringBuilder();
		for(String s : protocol) {
			output.append(s);
		}
		String st = output.toString();
		output = new StringBuilder("Protocol type : ");
		if(st.equals("0800")) {
			output.append("IPv4 (0x0800)");
		} else {
			output.append("Unknown");
		}
		
		//System.out.println(output.toString());
		
		return output.toString();
	}
	
	public String getHLen() {
		StringBuilder output = new StringBuilder();
		for(String s : hlen) {
			output.append(s);
		}
		String s = output.toString();
		int hsize = Integer.parseInt(s, 16);
		s = "Hardware size : " + hsize;
		
		
		//System.out.println(s);
		
		return s;
	}
	
	public String getPLen() {
		StringBuilder output = new StringBuilder();
		for(String s : plen) {
			output.append(s);
		}
		String s = output.toString();
		int psize = Integer.parseInt(s, 16);
		s = "Protocol size : " + psize;
		
		
		//System.out.println(s);
		
		return s;
	}
	
	public String getOperation() {
		StringBuilder sb = new StringBuilder();
		for(String s : operation) {
			sb.append(s);
		}
		int op = Integer.parseInt(sb.toString(), 16);
		sb = new StringBuilder("Opcode : ");
		
		if(op == 1) {
			sb.append("Request (" + op + ")");
		} else if (op == 2) {
			sb.append("Reply (" + op + ")");
		} else if (op == 3) {
			sb.append("Reverse request (" + op + ")");
		} else {
			sb.append("Reverse reply (" + op + ")");
		}
			
		
		//System.out.println(sb.toString());
		return sb.toString();
		
	}

	public String getSenderHA() {
		StringBuilder sb = new StringBuilder("Sender MAC adress : ");
		for(String s : senderHA) {
			sb.append(s);
			sb.append(":");
		}
		sb.setLength(sb.length()-1);
		//System.out.println(sb.toString());
		return sb.toString();
	}
	
	public String getSenderIA() {
		StringBuilder sb = new StringBuilder("Sender IP adress : ");
		for(String s : senderIA) {
			s = "" + Integer.parseInt(s, 16);
			sb.append(s);
			sb.append(".");
		}
		sb.setLength(sb.length()-1);
		//System.out.println(sb.toString());
		return sb.toString();
	}
	
	public String getTargetHA() {
		StringBuilder sb = new StringBuilder("Target MAC adress : ");
		for(String s : targetHA) {
			sb.append(s);
			sb.append(":");
		}
		sb.setLength(sb.length()-1);
		//System.out.println(sb.toString());
		return sb.toString();
	}
	
	public String getTargetIA() {
		StringBuilder sb = new StringBuilder("Target IP adress : ");
		for(String s : targetIA) {
			s = "" + Integer.parseInt(s, 16);
			sb.append(s);
			sb.append(".");
		}
		sb.setLength(sb.length()-1);
		//System.out.println(sb.toString());
		return sb.toString();
	}
	
	public String analyze() {
		StringBuilder output = new StringBuilder();
		StringBuilder sb = new StringBuilder();
		for(String s : operation) {
			sb.append(s);
		}
		if(Integer.parseInt(sb.toString(), 16) < 3) {
			output.append("Address Resolution Protocol :\n");
		} else {
			output.append("Reverse Address Resolution Protocol\n");
		}
		output.append("\t" + getHardware() + "\n");
		output.append("\t" +getProtocol() + "\n");
		output.append("\t" +getHLen() + "\n");
		output.append("\t" +getPLen() + "\n");
		output.append("\t" +getOperation() + "\n");
		output.append("\t" +getSenderHA() + "\n");
		output.append("\t" +getSenderIA() + "\n");
		output.append("\t" +getTargetHA() + "\n");
		output.append("\t" +getTargetIA() + "\n\n");
		
		return output.toString();
	}
}
	
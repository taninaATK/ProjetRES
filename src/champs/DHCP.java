package champs;

import java.util.ArrayList;
import java.util.List;
import java.net.IDN;

import TraceAnalyzer.TraceManager;

public class DHCP implements Champs {
	private String opCode; //1 o
	private String htype; //1 o
	private String hlen; //1 o
	private String hops; //1 o
	private String transID; //4 o
	private String seconds; //2 o
	private String flags; // 2 o
	private String[] clientIP; //4 o
	private String[] yourIP; //4 o
	private String[] serverIP; //4 o
	private String[] gatewayIP;//4 o
	private String[] clientHW; //Sur 16 octets
	private String[] serverName; //Sur 64 octets
	private String[] bootfileName; //Sur 128 octets
	private String mCookie; //Sur 8 octets
	private List<String[]> options;
	//Format de l'option opt1 -> opt2 -> opt3
	//où chaque opt(i) est un tableau des octets d'options
	private int overload = 0;
	
	public DHCP(String oc, String ht, String hl, String hop, String trans, String sec, String f, String[] client, 
			String[] yours, String[] server, String[] gateway, String[] clientH, String[] serverN, String[] bootfile,
			String cookie, List<String[]> opt) {
		opCode = oc; htype = ht; hlen = hl; hops = hop; transID = trans; seconds = sec; clientIP = client; yourIP = yours;
		serverIP = server; gatewayIP = gateway; clientHW = clientH; serverName = serverN; bootfileName = bootfile;
		mCookie = cookie; options = new ArrayList<String[]>(opt);
		
		
		//Conversion en bianire des flags
		int i = Integer.parseInt(f, 16);
		String f1 = Integer.toBinaryString(i); //On convertit en binaire
		flags = String.format("%" + 16 + "s", f1).replaceAll(" ", "0"); //on ajoute les 0 pour atteindre 16 bits
		
	}
	
	public int getOpCode() {
		return Integer.parseInt(opCode, 16);
	}
	
	public String getOpString() {
		if(getOpCode() == 1) {
			return "Boot Request (1)";
		}
		if(getOpCode() == 2) {
			return "Boot Reply (2)";
		}
		return "Unsupported operation";
	}
	
	public String getHType() {
		if(Integer.parseInt(htype, 16) == 1) {
			return "Ethernet 0x" + htype;
		}
		
		return "Unknown hardware type";
	}	
	
	public int getHLen() {
		return Integer.parseInt(hlen, 16);
	}
	
	public int getHops() {
		return Integer.parseInt(hops, 16);
	}

	public String getTransID() {
		return transID;
	}
	
	public int getSeconds() {
		return Integer.parseInt(seconds, 16);
	}

	public String getFlags() {
		StringBuilder output = new StringBuilder("\n\t\t" + flags.charAt(0));
		output.append("... .... .... .... = Broadcast flag : ");
		if(flags.charAt(0) == '0') {
			output.append("Unicast \n\t\t");
		} else {
			output.append("Broadcast \n\t\t");
		}
		output.append(".000 0000 0000 0000 = Reserved flags : 0x0000");
		return output.toString();
	}
	
	public String getClientIP() {
		return makeIP(clientIP);
	}
	
	public String getYourIP() {
		return makeIP(yourIP);
	}
	
	public String getServerIP() {
		return makeIP(serverIP);
	}
	
	public String getGatewayIP() {
		return makeIP(gatewayIP);
	}
	
	public String getClientHW() {
		StringBuilder output = new StringBuilder();
		for(int i = 0; i < getHLen(); i++) {
			output.append(clientHW[i]);
			output.append(':');
		}
		output.deleteCharAt(output.length()-1);
		output.append("\n\tClient Hardware address padding :");
		if(getHLen() == clientHW.length) {
			output.append("none");
		} else {
			for(int i = getHLen(); i < clientHW.length; i++) {
				output.append(clientHW[i]);
			}
		}
		return output.toString();
	}
	
	public String getServerName() {
		if(serverName[0].equals("00")) {
			return "not given.";
		}
		StringBuilder output = new StringBuilder();
		int i = Integer.parseInt(serverName[0], 16);
		while(i != 0) {
			output.append((char) i);
		}
		return output.toString();
	}
	
	public String getFileName() {
		if(bootfileName[0].equals("00")) {
			return "not given.";
		}
		StringBuilder output = new StringBuilder();
		int i = Integer.parseInt(bootfileName[0], 16);
		while(i != 0) {
			output.append((char) i);
		}
		return output.toString();
	}
	
	public String getCookie() {
		if(mCookie.equals("63825363")) {
			return "DHCP";
		}
		return "Unsupported";
	}
	
	public String scanAllOptions(){
		StringBuilder output = new StringBuilder();
		for (String[] opt : options) {
			output.append("Option :");
			output.append(scanOption(opt));
			output.append("\n\t");
		}
		return output.toString();
	}
	
	public String scanOption(String[] option) {
		StringBuilder output = new StringBuilder();
		int i = Integer.parseInt(option[0], 16);
		
		output.append("(" + i + ")\n\t\t");
		if(i != 0 && i != 255 && i != 80) {
			output.append("Length : ");
			output.append(Integer.parseInt(option[1], 16));
			output.append("\n\t\t");
		}
		switch (i) {
			case 0 :
				output.append("Padding : ");
				for(String pad : option) { output.append(pad);}
				break;
				
			case 1 : 
				output.append("Subnet Mask : ");
				for(int j = 2; j-2 < Integer.parseInt(option[1], 16); j++) {
					output.append(Integer.parseInt(option[j], 16));
					output.append('.');
				}
				output.deleteCharAt(output.length() - 1);
				break;
				
			case 2 :
				output.append("Time Offset : ");
				String s = TraceManager.toString(option);
				output.append(Integer.parseInt(s, 16));
				output.append(" seconds");
				break;
				
			case 3 : 
				output.append("Router : ");
				for(int j = 2; j-2 < Integer.parseInt(option[1], 16); j++) {
					//Si on est au début d'une nouvelle IP routeur et pas à la dernière ni la première : on va à la ligne
					if((j - 2) % 4 == 0 && j > 2 && j-2 != Integer.parseInt(option[1], 16)) {
						output.append("\n\t\t");
					}
					output.append(Integer.parseInt(option[j], 16));
					//Si on est pas au dernier octet d'une IP router <=> j  - 2 % 4 != 3
					if((j-2) % 4 != 3) {
						output.append('.');
					}
				}
				break;
				
			case 4 :
				output.append("Time Server :\n\t\t");
				for(int j = 2; j-2 < Integer.parseInt(option[1], 16); j++) {
					//Si on est au début d'une nouvelle IP et pas à la dernière ni la première : on va à la ligne
					if((j - 2) % 4 == 0 && j > 2 && j-2 != Integer.parseInt(option[1], 16)) {
						output.append("\n\t\t");
					}
					output.append(Integer.parseInt(option[j], 16));
					//Si on est pas au dernier octet d'une IP <=> j  - 2 % 4 != 3
					if((j-2) % 4 != 3) {
						output.append('.');
					}
				}
				break;
			
			case 5 : 
				output.append("Name Server :\n\t\t");
				for(int j = 2; j-2 < Integer.parseInt(option[1], 16); j++) {
					//Si on est au début d'une nouvelle IP et pas à la dernière ni la première : on va à la ligne
					if((j - 2) % 4 == 0 && j > 2 && j-2 != Integer.parseInt(option[1], 16)) {
						output.append("\n\t\t");
					}
					output.append(Integer.parseInt(option[j], 16));
					//Si on est pas au dernier octet d'une IP <=> j  - 2 % 4 != 3
					if((j-2) % 4 != 3) {
						output.append('.');
					}
				}
				break;
				
			case 6 :
				output.append("Domain Server :");
				for(int j = 2; j-2 < Integer.parseInt(option[1], 16); j++) {
					//Si on est au début d'une nouvelle IP et pas à la dernière ni la première : on va à la ligne
					if((j - 2) % 4 == 0 && j > 2 && j-2 != Integer.parseInt(option[1], 16)) {
						output.append("\n\t\t");
					}
					output.append(Integer.parseInt(option[j], 16));
					//Si on est pas au dernier octet d'une IP <=> j  - 2 % 4 != 3
					if((j-2) % 4 != 3) {
						output.append('.');
					}
				}
				break;
				
			case 7 :
				output.append("Log Server :\n\t\t");
				for(int j = 2; j-2 < Integer.parseInt(option[1], 16); j++) {
					//Si on est au début d'une nouvelle IP et pas à la dernière ni la première : on va à la ligne
					if((j - 2) % 4 == 0 && j > 2 && j-2 != Integer.parseInt(option[1], 16)) {
						output.append("\n\t\t");
					}
					output.append(Integer.parseInt(option[j], 16));
					//Si on est pas au dernier octet d'une IP <=> j  - 2 % 4 != 3
					if((j-2) % 4 != 3) {
						output.append('.');
					}
				}
				break;
				
			case 8 :
				output.append("Quotes Server :\n\t\t");
				for(int j = 2; j-2 < Integer.parseInt(option[1], 16); j++) {
					//Si on est au début d'une nouvelle IP et pas à la dernière ni la première : on va à la ligne
					if((j - 2) % 4 == 0 && j > 2 && j-2 != Integer.parseInt(option[1], 16)) {
						output.append("\n\t\t");
					}
					output.append(Integer.parseInt(option[j], 16));
					//Si on est pas au dernier octet d'une IP <=> j  - 2 % 4 != 3
					if((j-2) % 4 != 3) {
						output.append('.');
					}
				}
				break;
				
			case 9 :
				output.append("LPR Server :\n\t\t");
				for(int j = 2; j-2 < Integer.parseInt(option[1], 16); j++) {
					//Si on est au début d'une nouvelle IP et pas à la dernière ni la première : on va à la ligne
					if((j - 2) % 4 == 0 && j > 2 && j-2 != Integer.parseInt(option[1], 16)) {
						output.append("\n\t\t");
					}
					output.append(Integer.parseInt(option[j], 16));
					//Si on est pas au dernier octet d'une IP <=> j  - 2 % 4 != 3
					if((j-2) % 4 != 3) {
						output.append('.');
					}
				}
				break;
				
			case 10 :
				output.append("Impress Server :\n\t\t");
				for(int j = 2; j-2  < Integer.parseInt(option[1], 16); j++) {
					//Si on est au début d'une nouvelle IP et pas à la dernière ni la première : on va à la ligne
					if((j - 2) % 4 == 0 && j > 2 && j-2 != Integer.parseInt(option[1], 16)) {
						output.append("\n\t\t");
					}
					output.append(Integer.parseInt(option[j], 16));
					//Si on est pas au dernier octet d'une IP <=> j  - 2 % 4 != 3
					if((j-2) % 4 != 3) {
						output.append('.');
					}
				}
				break;
				
			case 11 :
				output.append("RLP Server :\n\t\t");
				for(int j = 2; j-2  < Integer.parseInt(option[1], 16); j++) {
					//Si on est au début d'une nouvelle IP et pas à la dernière ni la première : on va à la ligne
					if((j - 2) % 4 == 0 && j > 2 && j-2  != Integer.parseInt(option[1], 16)) {
						output.append("\n\t\t");
					}
					output.append(Integer.parseInt(option[j], 16));
					//Si on est pas au dernier octet d'une IP <=> j  - 2 % 4 != 3
					if((j-2) % 4 != 3) {
						output.append('.');
					}
				}
				break;
				
			case 12 : 
				output.append("Hostname : ");
				for(int j = 2; j-2 < Integer.parseInt(option[1], 16); j++) {
					output.append((char) Integer.parseInt(option[j], 16));
				}
				break;
				
			case 13 :
				output.append("Boot File Size : ");
				//Ici la length est toujours de 2
				if(Integer.parseInt(option[1], 16) != 2) {
					output.append("Option en erreur");
				} else {
					String s1 = option[2] + option[3];
					output.append(Integer.parseInt(s1, 16));
					output.append("chunks of 512 bytes");
				}
				break;
				
			case 14 :
				output.append("Merit Dump File : ");
				for(int j = 2; j-2 < Integer.parseInt(option[1], 16); j++) {
					output.append((char) Integer.parseInt(option[j], 16));
				}
				break;
				
			case 15 :
				output.append("Domain Name : ");
				for(int j = 2; j-2 < Integer.parseInt(option[1], 16); j++) {
					output.append((char) Integer.parseInt(option[j], 16));
				}
				break;
				
			case 16 :
				output.append("Swap server address : ");
				for(int j = 2; j-2  < Integer.parseInt(option[1], 16); j++) {
					//Si on est au début d'une nouvelle IP et pas à la dernière ni la première : on va à la ligne
					if((j - 2) % 4 == 0 && j > 2 && j-2  != Integer.parseInt(option[1], 16)) {
						output.append("\n\t\t");
					}
					output.append(Integer.parseInt(option[j], 16));
					//Si on est pas au dernier octet d'une IP <=> j  - 2 % 4 != 3
					if((j-2) % 4 != 3) {
						output.append('.');
					}
				}
				break;
				
			case 17 :
				output.append("Path name for root disk : ");
				for(int j = 1; j-1 < Integer.parseInt(option[1], 16); j++) {
					output.append((char) Integer.parseInt(option[j], 16));
				}
				break;
				
			case 18 :
				output.append("Path name for more BOOTP info : ");
				for(int j = 1; j-1 < Integer.parseInt(option[1], 16); j++) {
					output.append((char) Integer.parseInt(option[j], 16));
				}
				break;
				
			case 19 :
				output.append("Enable/Disable IP Forwarding : ");
				if(!option[1].equals("01")) {
					output.append("error");
				} else {
					int value = Integer.parseInt(option[2]);
					if(value == 1) {
						output.append("Enabled (0x01)");
					} else {
						output.append("Disabled (0x00)");
					}
				}
				break;
				
			case 20 :
				output.append("Enable/Disable Source Routing : ");
				if(!option[1].equals("01")) {
					output.append("error");
				} else {
					int value = Integer.parseInt(option[2]);
					if(value == 1) {
						output.append("Enabled (0x01)");
					} else {
						output.append("Disabled (0x00)");
					}
				}
				break;
				
			case 21 :
				output.append("Routing Policy Filter : ");
				for(int j = 2; j-2  < Integer.parseInt(option[1], 16); j++) {
					//Si on est au début d'une nouvelle IP et pas à la dernière ni la première : on va à la ligne
					if((j - 2) % 8 == 0 && j > 2 && j-2  != Integer.parseInt(option[1], 16)) {
						output.append("\n\t\t");
					}
					if(j-2 % 4 == 4 && j-2 % 8 != 0) {
						output.append("IP : ");
					}
					
					if(j-2 % 8 == 0) {
						output.append("\tMask : ");
					}
					
					output.append(Integer.parseInt(option[j], 16));
					//Si on est pas au dernier octet d'une IP <=> j  - 2 % 4 != 3
					if((j-2) % 4 != 3) {
						output.append('.');
					}
				}
				break;
				
			case 22 :
				output.append("Max Datagram Reassembly Size : ");
				if(Integer.parseInt(option[1], 16) == 2) {
					output.append(Integer.parseInt(option[2] + option[3], 16));
				} else {
					output.append("error");
				}
				break;
				
			case 23 :
				output.append("Default IP Time to Live : ");
				if(Integer.parseInt(option[1], 16) != 1) {
					output.append("error");
				} else {
					output.append(Integer.parseInt(option[2], 16));
				}
				break;
				
			case 24 :
				output.append("MTU Timeout : ");
				if(Integer.parseInt(option[1], 16) != 4) {
					output.append("error");
				} else {
					StringBuilder sb = new StringBuilder();
					for(int j = 2; j < option.length; j++) {
						sb.append(option[j]);
					}
					output.append(Integer.parseInt(sb.toString(), 16) + " seconds");
				}
				
			case 28 :
				output.append("Broadcast Address : ");
				for(int j = 2; j-2 < Integer.parseInt(option[1], 16); j++) {
					output.append(Integer.parseInt(option[j], 16) + ".");
				}
				output.deleteCharAt(output.length() - 1);
				break;
				
			case 50 :
				output.append("Requested IP Address : ");
				for(int j = 2; j-2 < Integer.parseInt(option[1], 16); j++) {
					output.append(Integer.parseInt(option[j], 16) + '.');
				}
				output.deleteCharAt(output.length() - 1);
				break;
				
			case 51 : //Temps de validité IP
				output.append("IP Address Lease Time : ");
				StringBuilder time = new StringBuilder();
				for(int j = 2; j < option.length; j++) {
					time.append(option[j]);
				}
				int seconds = Integer.parseInt(time.toString(), 16);
				output.append("(" + seconds + "s) ");
				long sec = seconds % 60;
				long min = seconds % 3600 / 60;
				long h = seconds % 86400 / 3600;
				long jours = seconds / 86400;
				output.append(jours + " days " + h +" hours " + min + " minutes " + sec + " seconds");
				break;
				
			case 52 :
				output.append("Overload : ");
				switch (Integer.parseInt(option[2], 16)) {
					case 1 :
						overload = 1;
						output.append("sname");
						break;
					case 2 :
						overload = 2;
						output.append("file");
						break;
					case 3 :
						overload = 3;
						output.append("sname and file");
						break;
						
					default :
						output.append("unknown");
				}
				break;
				
			case 53 :
				if(Integer.parseInt(option[1], 16) != 1) {
					output.append("option en erreur");
				} else {
					output.append("DHCP Message Type ");
					switch (Integer.parseInt(option[2])){
						case 1 :
							output.append("(Discover)");
							break;
						case 2 :
							output.append("(Offer)");
							break;
							
						case 3 :
							output.append("(Request)");
							break;
							
						case 4 :
							output.append("(Decline)");
							break;
							
						case 5 :
							output.append("(ACK)");
							break;
							
						case 6 :
							output.append("(NAK)");
							break;
						
						case 7 :
							output.append("(RELEASE)");
							break;
							
						case 8 :
							output.append("(INFORM)");
							break;
							
						default : 
							output.append("(UNKNOWN)");
					}
				}
				break;
				
			case 54 :
				output.append("DHCP Server Identifier : ");
				for(int j = 2; j < option.length; j++) {
					output.append(Integer.parseInt(option[j], 16));
					if(j!= option.length -1) {
						output.append('.');
					}
				}
				break;
				
			case 55 :
				output.append("Parameter Request List : \n\t\t\t");
				for(int j = 2; j < option.length; j++) {
					output.append("Item : " + Integer.parseInt(option[j], 16));
					if(j!= option.length -1) {
						output.append("\n\t\t\t");
					}
				}
				break;
			
			case 56 :
				output.append("DHCP Error Message : ");
				for(int j = 2; j < option.length; j++) {
					output.append((char) Integer.parseInt(option[j], 16));
				}
				break;
				
			case 57 :
				output.append("DHCP Maximum Message Size : ");
				if(Integer.parseInt(option[1], 16) != 2) {
					output.append("error");
				} else {
					output.append(Integer.parseInt(option[2] + option[3], 16) + " bytes");
				}
				break;
				
			case 58 :
				output.append("Renewal time value : ");
				time = new StringBuilder();
				for(int j = 2; j< option.length; j++) {
					time.append(option[j]);
				}
				seconds = Integer.parseInt(time.toString(), 16);
				output.append("(" + seconds + "s) ");
				sec = seconds % 60;
				min = seconds % 3600 / 60;
				h = seconds % 86400 / 3600;
				jours = seconds / 86400;
				output.append(jours + " days " + h +" hours " + min + " minutes " + sec + " seconds");
				break;
				
			case 59 :
				output.append("Rebinding time value : ");
				time = new StringBuilder();
				for(int j = 2; j< option.length; j++) {
					time.append(option[j]);
				}
				seconds = Integer.parseInt(time.toString(), 16);
				output.append("(" + seconds + "s) ");
				sec = seconds % 60;
				min = seconds % 3600 / 60;
				h = seconds % 86400 / 3600;
				jours = seconds / 86400;
				output.append(jours + " days " + h +" hours " + min + " minutes " + sec + " seconds");
				break;
				
			case 61 :
				output.append("Client Identifier : ");
				if(Integer.parseInt(option[2], 16) == 1) {
					output.append("\n\t\t\tType : Ethernet 0x" + option[2] + "\n\t\t\tAddress : ");
				} else {
					output.append("Unknown hardware type");
				}
				for(int j = 3; j-3 < Integer.parseInt(option[1], 16) - 1; j++) {
					output.append(option[j] + ":");
				}
				output.deleteCharAt(output.length()-1);
				
				break;
				
			case 220 :
				output.append("Subnet Allocation Option");
				break;
				
			case 221 :
				output.append("Virtual Subnet Selection (VSS)");
				break;
				
			case 255 :
				output.append("Option End : 255");
				break;
			default :
				output.append("Option Reserved (private use), unassigned or vendor specific");
		}
		return output.toString();
	}
	
	public String analyze() {
		String options = scanAllOptions();
		StringBuilder output = new StringBuilder("Dynamic Host Configuration Protocol \n\t");
		output.append("Message Type :" + getOpString() + "\n\t");
		output.append("Hardware Type : " + getHType() + "\n\t");
		output.append("Hardware Address Length " + getHLen() + "\n\t");
		output.append("Hops :" + getHops() + "\n\t");
		output.append("Transaction ID : 0x" + getTransID() + "\n\t");
		output.append("Seconds elapsed : " + getSeconds() + "\n\t");
		output.append("Bootp Flags :" + getFlags() + "\n\t");
		output.append("Client IP address : " + getClientIP() + "\n\t");
		output.append("Your (client) IP address : " + getYourIP() + "\n\t");
		output.append("Next Server IP address : " + getServerIP() + "\n\t");
		output.append("Relay agent IP address : " + getGatewayIP() + "\n\t");
		output.append("Client MAC address : " + getClientHW() +"\n\t");
		switch (overload) {
			case 1 :
				output.append("Overloaded Option :" + scanOption(serverName) + "\n\t");
				output.append("Boot file name : " + getFileName() + "\n\t");
				break;
			case 2 :
				output.append("Server host name : " + getServerName() + "\n\t");
				output.append("Overloaded Option :" + scanOption(bootfileName) + "\n\t");
				break;
		
			case 3 :
				output.append("Overloaded Option :" + scanOption(serverName) + "\n\t");
				output.append("Overloaded Option :" + scanOption(bootfileName) + "\n\t");
				break;
			
			default :
				output.append("Server host name : " + getServerName() + "\n\t");
				output.append("Boot file name : " + getFileName() + "\n\t");
				
		}
		output.append("Magic Cookie : " + getCookie() + "\n\t");
		output.append(options);
		
		return output.toString();
	}

	private static String makeIP(String[] ip) {
		StringBuilder output = new StringBuilder();
		for(String s : ip) {
			output.append(Integer.parseInt(s, 16));
			output.append('.');
		}
		output.deleteCharAt(output.length()-1);
		return output.toString();
	}
}

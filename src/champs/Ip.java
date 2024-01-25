package champs;

import java.util.Arrays;

/** Classe permettant de représenter la couche IP
 *
 */

public class Ip implements Champs {
	private String version; //Version IP
	private String ihl; //Longueur de l'en-tête
	private String tos; //Type of Service
	private String[] total_length; //Longueur totale du datagramme
	private String[] identification; //Identifiant du msg si fragmenté
	private String flags; //fragmenté? fragmentable? autres fragments?
	private String offset; //position du fragment dans le message initial
	private String ttl; //Time to Live
	private String protocol; //protocole encapsulé
	private HeaderCheck header_checksum; //vérification erreurs sur le header
	private String[] sourceIP; //adresse IP de la source
	private String[] destIP; //addresse IP de la destination
	private String[] options; //Liste des options

	public Ip(String version, String ihl, String tos, String[] length, String[] id, String[] flags_offset, String ttl, String proto, HeaderCheck checksum, String[] source, String[] dest, String[] opt) {
		this.version = version;
		this.ihl = ihl;
		this.tos = tos;
		this.total_length = length;
		this.identification = id;
		int i = Integer.parseInt(flags_offset[0] + flags_offset[1], 16);
		String f_o_binary = Integer.toBinaryString(i); //On converti les flags_off en binaire
		String f_o_format = String.format("%" + 16 + "s", f_o_binary).replaceAll(" ", "0");
		this.flags = f_o_format.substring(0,3);
		this.offset = f_o_format.substring(3,16);	
		this.ttl = ttl;
		this.protocol = proto;
		this.header_checksum = checksum;
		this.sourceIP = Arrays.copyOf(source, source.length);
		this.destIP = Arrays.copyOf(dest, dest.length);
		this.options = Arrays.copyOf(opt, opt.length);
	}
	
	//Getter pour la version d'IP
	public String getVersion() {
		return version;
	}
	
	//Avoir la version en lisible
	public String getVersionDec() {
		if(this.getVersion().equals("04")) {
			return "IPv4";
		} else {
			return "IPv6";
		}
	}
	
	//Getter pour ihl
	public String getIHL() {
		return ihl;
	}
	
	//IHL en lisible
	public String getIHLDec() {
		int taille = Integer.parseInt(this.getIHL(), 16) * 4; //IHL s'exprime en nb de 32 bits = en 4 octets
		return taille + " octets";
	}
	
	//Recuperation de l'IP source en hexa, comme dans la trace
	public String getSourceIP() {
		StringBuilder output = new StringBuilder();
		for(String s : sourceIP) {
			output.append(s);
			output.append(" ");
		}
		
		return output.toString();
	}
	
	//Recuperation de l'IP destination en hexa, comme dans la trace
		public String getDestIP() {
			StringBuilder output = new StringBuilder();
			for(String s : destIP) {
				output.append(s);
				output.append(" ");
			}
			
			return output.toString();
		}

	//Recuperation de l'IP source en décimal format decimal.decimal.decimal.decimal
	public String getIPDec(String[] ip) {
		StringBuilder output = new StringBuilder(); //Construction de la sortie
		for(int i = 0; i < ip.length; i++) {
			//conversion de l'octet en décimal
			output.append(Integer.parseInt(ip[i], 16));
			if(i < ip.length -1) {
				output.append('.');
			}
		}
		return output.toString();
	}
	
	public int getHeaderLength() {
		return Integer.parseInt(ihl) * 4;
	}
	
	public String getTotalLength() {
		return Integer.parseInt(total_length[0]+total_length[1], 16) + "";
	}
	
	public String getIdentification() {
		return identification[0]+identification[1];
	}
	public int getIdentificationDec() {
		return Integer.parseInt(getIdentification(), 16);
	}
	
	public String getFlags() {
		return flags;
	}
	
	public String getFlagsFormatted() {
		StringBuilder sb = new StringBuilder("Flags : 0x" + getFlags() +"\n");
		sb.append("\t\t" + flags.substring(0, 1) + "... .... .... .... ");
		if(flags.charAt(0) == '0') {
			sb.append("= Reserved bit : not set\n");
		} else {
			sb.append("= Reserved bit : set\n");
		}
		
		sb.append("\t\t." + flags.substring(1, 2) + ".. .... .... .... ");
		if(flags.charAt(1) == '0') {
			sb.append("= Don't fragment : not set\n");
		} else {
			sb.append("= Don't fragment : set\n");
		}
		
		sb.append("\t\t.." + flags.substring(2, 3) + ". .... .... .... ");
		if(flags.charAt(2) == '0') {
			sb.append("= More fragments : not set");
		} else {
			sb.append("= More fragments fragment : set");
		}
		return sb.toString();
	}
	
	public String getTos() {
		return tos;
	}
	
	public int getOffset() {
		return Integer.parseInt(offset, 16)/8;
	}
	
	public String getTTL() {
		return ttl;
	}
	public int getTTLDec() {
		return Integer.parseInt(getTTL(), 16);
	}
	
	public String getProtocol(){
		return protocol;
	}
	
	public String getProtocolName() {
		if (protocol.equals("01")) {
			return "ICMP";
		}
		
		if (protocol.equals("02")) {
			return "IGMP";
		}
		
		if (protocol.equals("06")) {
			return "TCP";
		}
		
		if(protocol.equals("08")) {
			return "EGP";
		}
		
		if(protocol.equals("09")) {
			return "IGP";
		}
		
		if(protocol.equals("11")) {
			return "UDP";
		}
		
		if(protocol.equals("24")) {
			return "XTP";
		}
		
		if(protocol.equals("2e") || protocol.equals("2E")) {
			return "RSVP";
		}
		
		return "non connu";
		
	}
	
	@Override
	public String analyze() {
		StringBuilder ip = new StringBuilder();
		ip.append("\nInternet Protocol\n\tVersion: "+ getVersion() + "\n");
		ip.append("\tType of service: 0x" + getTos() + "\n");
		ip.append("\tHeader length: " + getHeaderLength() + " octets \n");
		ip.append("\tTotal Length: " + getTotalLength() +" octets \n");
		ip.append("\tIdentification: 0x" + getIdentification() + " (" + getIdentificationDec() +")\n");
		ip.append("\t" + getFlagsFormatted() + "\n");
		ip.append("\tFragment offset :" + getOffset() + "\n");
		ip.append("\tTime to live: " + getTTLDec() + "\n");
		ip.append("\tProtocol: " + getProtocolName() + " (" + getProtocol() + ")\n");
		ip.append("\tHeader checksum: 0x" + header_checksum.getChecksum() + "\n"); //+ " [" + header_checksum.getCheck() + "]\n");
		ip.append("\tIP Source: " + getIPDec(sourceIP) + "\n");
		ip.append("\tIP Destination: " + getIPDec(destIP) + "\n\n");
		return ip.toString();
	}

	
	
}
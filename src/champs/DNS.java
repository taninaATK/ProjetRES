package champs;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class DNS implements Champs {
	private String[] dns;
	private String[] id;
	private String[] flags;
	private String[] nbQuestions;
	private String[] nbAnswerRR;
	private String[] nbAuthorityRR;
	private String[] nbAdditionnalRR;
	private String[] sections;
	private int p_sections = 0;//pointeur sur octet courant de la section
	private int d_sections = 0;
	private int g_sections = 0;
	
	
	public DNS(String[] dns, String[] id, String[] flags, String[] nbQuestions, String[] nbAnswerRR, String[] nbAuthorityRR,
			String[] nbAdditionnalRR, String[] sections) {
		this.dns = dns;
		this.id = id;
		this.flags = flags;
		this.nbQuestions = nbQuestions;
		this.nbAnswerRR = nbAnswerRR;
		this.nbAuthorityRR = nbAuthorityRR;
		this.nbAdditionnalRR = nbAdditionnalRR;
		this.sections = sections; 
	}


	public String getIdHex() {
		return id[0] + id[1];
	}

	public int getFlagsDec() {
		return Integer.parseInt(getFlags(), 16);
	}

	public String getFlags() {
		return flags[0] + flags[1];
	}
	
	public String getFlagsFormat() {
		StringBuilder output = new StringBuilder();
		output.append("\t Flags : 0x" + getFlags());
		String f = hexToBin(getFlags());
		if(f.substring(0,1).equals("0")) {
			output.append(" Standard query\n");
			output.append("\t\t0... .... .... .... = Response: Message is a query\n");
		}
		
		if(f.substring(0,1).equals("1")) {
			output.append(" Standard query response\n");
			output.append("\t\t1... .... .... .... = Response: Message is a response\n");
		}
		
		if(f.substring(1, 5).equals("0000")) {
			output.append("\t\t.000 0... .... .... = Opcode: Standard query (0)\n");
		}
		
		//regarder les autres types Opcode
		//regarder Authoritative Answer f.substring(5,6)
		
		if(f.substring(5,6).equals("0")) {
			output.append("\t\t.... .0.. .... .... = Authoritative: Server is not an authority for domain\n");
		}
		
		if(f.substring(6, 7).equals("0")) {
			output.append("\t\t.... ..0. .... .... = Truncated: Message is not truncated\n");
		}
		
		if(f.substring(6, 7).equals("1")) {
			output.append("\t\t.... ..1. .... .... = Truncated: Message is truncated\n");
		}
		
		if(f.substring(7, 8).equals("1")) {
			output.append("\t\t.... ...1 .... .... = Recursion desired: Do query recursively\n");
		}
		
		if(f.substring(8, 9).equals("1")) {
			output.append("\t\t.... .... 1... .... = Recursion available: Server can do recursive queries\n");
		}
		
		if(f.substring(9, 10).equals("0")) {
			output.append("\t\t.... .... .0.. .... = Z: reserved (0)\n");
		}
		
		if(f.substring(0, 1).equals("1") &&  f.substring(10, 11).equals("0")) {
			output.append("\t\t.... .... ..0. .... = Answer authenticated: Answer/authority portion was not authenticated by the server\n");
		}
		
		if(f.substring(11, 12).equals("0")) {
			output.append("\t\t.... .... ...0 .... = Non-authenticated data: Unacceptable\n");
		}
		
		if(f.substring(0, 1).equals("1")) {
			if(f.substring(12, 16).equals("0000")) {
				output.append("\t\t.... .... .... 0000 = Reply code : No error (0)\n");
			}
			
			if(f.substring(12, 16).equals("0001")) {
				output.append("\t\t.... .... .... 0001 = Reply code : Format error (1)\n");
			}
			
			if(f.substring(12, 16).equals("0010")) {
				output.append("\t\t.... .... .... 0010 = Reply code : Server Failure (2)\n");
			}
			
			if(f.substring(12, 16).equals("0011")) {
				output.append("\t\t.... .... .... 0011 = Reply code : Non-Existent Domain (3)\n");
			}
			
			if(f.substring(12, 16).equals("0100")) {
				output.append("\t\t.... .... .... 0100 = Reply code : Not implemented (4)\n");
			}

			if(f.substring(12, 16).equals("0101")) {
				output.append("\t\t.... .... .... 0101 = Reply code : Query refused (5)\n");
			}

			if(f.substring(12, 16).equals("0110")) {
				output.append("\t\t.... .... .... 0110 = Reply code : Name exists when it should not (6)\n");
			}

			if(f.substring(12, 16).equals("0111")) {
				output.append("\t\t.... .... .... 0111 = Reply code : RR set exists when it should not (7)\n");
			}
			
			if(f.substring(12, 16).equals("1000")) {
				output.append("\t\t.... .... .... 1000 = Reply code : RR Set that should exist does not (8)\n");
			}
			
			if(f.substring(12, 16).equals("1001")) {
				output.append("\t\t.... .... .... 1001 = Reply code : Server Not Authoritative for zone (9)\n");
			}
			
		}
		
		return output.toString();
	}


	public String getNbQuestions() {
		return nbQuestions[0] + nbQuestions[1];
	}

	public String getNbQuestionsFormat() {
		return "\tQuestions: " + Integer.parseInt(getNbQuestions(), 16) + "\n";
	}

	public String getNbAnswerRR() {
		return nbAnswerRR[0] + nbAnswerRR[1];
	}

	public String getNbAnswerRRFormat() {
		return "\tAnswer RRs: " + Integer.parseInt(getNbAnswerRR(), 16) + "\n";
	}

	public String getNbAuthorityRR() {
		return nbAuthorityRR[0] + nbAuthorityRR[1];
	}

	public String getNbAuthorityRRFormat() {
		return "\tAuthority RRs: " + Integer.parseInt(getNbAuthorityRR(), 16) + "\n";
	}

	public String getNbAdditionnalRR() {
		return nbAdditionnalRR[0] + nbAdditionnalRR[1];
	}

	public String getNbAdditionnalRRFormat() {
		return "\tAdditional RRs: " + Integer.parseInt(getNbAdditionnalRR(), 16) + "\n";
	}

	public String[] getSections() {
		return sections;
	}
	
	public List<String> getCopySections() {
		List<String> copy = new ArrayList<>();
		for(int i = 0; i < sections.length; i++) {
			copy.add(sections[i]);
		}
		return copy;
	}
	
	public String[] getName(String[] sec, int i) {
		List<String> o_sec = new ArrayList<>();
		if(i < sec.length) {
			String etiq = sec[i] + sec[i+1];
			String etiq_bin = hexToBin(sec[i]);
			if (etiq_bin.substring(0,2).equals("11")) { //est ce que etiquette de compression?
				i++;
				String decalage = etiq_bin.substring(2) + hexToBin(sections[i]);
				int offset = Integer.parseInt(decalage, 2); //valeur du decalage en décimal
				while(!dns[offset].equals("00") && !(hexToBin(dns[offset]).substring(0,2).equals("11"))) {
					o_sec.add(dns[offset]);
					offset++;
				}
				if(dns[offset].equals("00")) {
					o_sec.add(dns[offset]); //on ajoute "00"
				}
				else {
					if(!(dns[offset]+dns[offset+1]).equals(etiq)) {
						o_sec.add(dns[offset]);
						o_sec.add(dns[offset+1]);
					}
				}
				
			}
			else { //si pas d'ï¿½tiquette de compression
				while(!sec[i].equals("00") && !(hexToBin(sec[i]).substring(0,2).equals("11"))) {
					o_sec.add(sec[i]);
					i++;
				}
				if(sec[i].equals("00")) {
					o_sec.add(sec[i]); //on ajoute "00"
				}
				else {
					o_sec.add(sec[i]);
					o_sec.add(sec[i+1]);
				}
			}
		}
		i++;
		g_sections = i;
		return toStringTab(o_sec);
	}
	
	//permet d'obtenir une section Question
	public String[] getQuestionSection() {
		List<String> queries = new ArrayList<>();
		int i = p_sections;
		
		if(i < sections.length) {
			String etiq = sections[i] + sections[i+1];
			String etiq_bin = hexToBin(sections[i]);
			if (etiq_bin.substring(0,2).equals("11")) { //est ce que etiquette de compression?
				i++;
				String decalage = etiq_bin.substring(2) + hexToBin(sections[i]);
				int offset = Integer.parseInt(decalage, 2); //valeur du decalage en décimal
				while(!dns[offset].equals("00") && !(hexToBin(dns[offset]).substring(0,2).equals("11"))) {
					queries.add(dns[offset]);
					offset++;
				}
				if(dns[offset].equals("00")) {
					queries.add(dns[offset]); //on ajoute "00"
				}
				else {
					if(!(dns[offset]+dns[offset+1]).equals(etiq)) {
						queries.add(dns[offset]);
						queries.add(dns[offset+1]);
					}
				}
				
			}
			else { //si pas d'ï¿½tiquette de compression
				while(!sections[i].equals("00")) {
					queries.add(sections[i]);
					i++;
				}
				queries.add(sections[i]); //on ajoute "00"
			}
			
			i++;
			for(int j = 0; j < 4; j++) { //ajout des champs QType et QClass
				queries.add(sections[i++]);
			}
			p_sections = i;
		}
		return toStringTab(queries);
	}


	public String[] getOtherSectionsRR() {
		List<String> o_sec = new ArrayList<>();
		int i = p_sections;
		
		if(i < sections.length) {
			String etiq = sections[i] + sections[i+1];
			String etiq_bin = hexToBin(sections[i]);
			if (etiq_bin.substring(0,2).equals("11")) { //est ce que etiquette de compression?
				i++;
				String decalage = etiq_bin.substring(2) + hexToBin(sections[i]);
				int offset = Integer.parseInt(decalage, 2); //valeur du decalage en décimal
				while(!dns[offset].equals("00") && !(hexToBin(dns[offset]).substring(0,2).equals("11"))) {
					o_sec.add(dns[offset]);
					offset++;
				}
				if(dns[offset].equals("00")) {
					o_sec.add(dns[offset]); //on ajoute "00"
				}
				else {
					if(!(dns[offset]+dns[offset+1]).equals(etiq)) {
						o_sec.add(dns[offset]);
						o_sec.add(dns[offset+1]);
					}
				}
				
			}
			else { //si pas d'ï¿½tiquette de compression
				while(!sections[i].equals("00")) {
					o_sec.add(sections[i]);
					i++;
				}
				o_sec.add(sections[i]); //on ajoute "00"
			}
			i++;
			for(int j = 0; j < 10; j++) { //ajout des champs Type, Class, TTL, Rdata_length
				o_sec.add(sections[i++]);
			}
			int data_length = Integer.parseInt(sections[i-2]+sections[i-1], 16);
			for(int j = 0; j < data_length; j++) { //ajout du champs Rdata
				o_sec.add(sections[i++]);
			}
			p_sections = i;
		}
		
		return toStringTab(o_sec);
	}

	
	public String lireLabel(String taille, String[] sect, int debut) {
		StringBuilder output = new StringBuilder();
		int length = Integer.parseInt(taille, 16);
		for(int i = 0 ; i < length; i++) {
			int str = Integer.parseInt(sect[debut], 16);
			output.append((char)str);
			debut++;
		}
		return output.toString();
	}
	
	public String getQuestionsFormat(String[] queries) {
		StringBuilder output = new StringBuilder();
		//champs QName
		output.append("\t\tName : ");
		int i = 0;
		d_sections = 0;
		output.append(decodeName(queries, d_sections));
		i=d_sections;
		
		//champs QType
		String type = queries[i] + queries[i+1];
		i += 2;
		output.append("\t\tType : " + getType(type) + "\n");
		
		//champs QClass
		String classe = queries[i] + queries[i+1];
		i += 2;
		output.append("\t\tClass : " + getClasse(classe) + "\n\n");
		
		return output.toString();
		
	}
	
	public String decodeName(String[] o_sec, int i) {
		StringBuilder output = new StringBuilder();
		
		while(!o_sec[i].equals("00")) {
			String taille = o_sec[i];
			String taille_bin = hexToBin(taille);
			if(taille_bin.substring(0,2).equals("11")) {
				i++;
				String decalage = taille_bin.substring(2) + hexToBin(o_sec[i]);
				int offset = Integer.parseInt(decalage, 2); //valeur du decalage en décimal
				if(o_sec.length != dns.length) {
					d_sections += i;
					d_sections++;
				}
				return output.append(decodeName(dns, offset)).toString();
				
				//i++;
			}
			else {
				i++;
				output.append(lireLabel(taille, o_sec, i) + ".");
				i += Integer.parseInt(taille,16);
			}
		}
		if(output.length() > 0) {
			output.setLength(output.length() -1);
			output.append("\n");
		}
		
		if(o_sec.length != dns.length) {
			d_sections = i;
			d_sections++;
		}

		return output.toString();
	}
	
	public String getRRFormat(String[] o_sec) {
		StringBuilder output = new StringBuilder();
		//champs QName
		output.append("\t\tName : ");
		int i = 0;
		d_sections = 0;
		output.append(decodeName(o_sec, d_sections));

		//output.setLength(output.length() -1);
		//output.append("\n");
		i=d_sections;
		//i++;
		

		
		//champs QType
		String type = o_sec[i] + o_sec[i+1];
		i += 2;
		output.append("\t\tType : " + getType(type) + "\n");
		
		//champs QClass
		String classe = o_sec[i] + o_sec[i+1];
		i += 2;
		output.append("\t\tClass : " + getClasse(classe) + "\n");
		
		//champs TTL
		String ttl = o_sec[i] + o_sec[i+1] + o_sec[i+2] + o_sec[i+3];
		i += 4;
		output.append("\t\tTTL : " + Integer.parseInt(ttl, 16) + "\n");
		
		//champs Rdata_length
		String data_length = o_sec[i] + o_sec[i+1];
		i += 2;
		output.append("\t\tData length : " + Integer.parseInt(data_length, 16) + "(octets) \n");
		
		//champs Rdata
		
		String[] data = new String[Integer.parseInt(data_length,16)];
		for(int j = 0; j < Integer.parseInt(data_length,16); j++) {
			data[j] = o_sec[i];
			i++;
		}
		
		int t = Integer.parseInt(type,16);
		if(t == 1) {
			output.append("\t\tAddress : " + Integer.parseInt(data[0], 16) + "." + Integer.parseInt(data[1], 16) + "." + Integer.parseInt(data[2], 16) + "." + Integer.parseInt(data[3], 16) + "\n");
		}
		
		if(t == 2) {
			output.append("\t\tNameServer : ");
			output.append(decodeName(data, 0));
			output.append("\n");
		}

		
		if(t == 5) {
			output.append("\t\tCNAME : ");
			output.append(decodeName(data, 0));
			output.append("\n");
		}
		
		if(t == 6) {
			String[] ch1 = getName(data, 0);
			String[] ch2 = getName(data, g_sections);
			output.append("\t\tPrimary name server : " + decodeName(ch1, 0));
			output.append("\t\tResponsible authority's mailbox : " + decodeName(ch2, 0));
			g_sections++;
			output.append("\t\tSerial Number : " +Long.parseLong(data[g_sections] + data[g_sections+1] + data[g_sections +2] + data[g_sections+3], 16) + "\n");
			g_sections += 4;
			output.append("\t\tRefresh Number : " +Long.parseLong(data[g_sections] + data[g_sections+1] + data[g_sections +2] + data[g_sections+3], 16) + "\n");
			g_sections += 4;
			output.append("\t\tRetry Interval : " +Long.parseLong(data[g_sections] + data[g_sections+1] + data[g_sections +2] + data[g_sections+3], 16) + "\n");
			g_sections += 4;
			output.append("\t\tExpire limit : " +Long.parseLong(data[g_sections] + data[g_sections+1] + data[g_sections +2] + data[g_sections+3], 16) + "\n");
			g_sections += 4;
			output.append("\t\tMinimum TTL : " +Long.parseLong(data[g_sections] + data[g_sections+1] + data[g_sections +2] + data[g_sections+3], 16) + "\n");
		}
		
		if(t == 12) {
			output.append("\t\tDomain Name : ");
			output.append(decodeName(data, 0));
			output.append("\n");
		}
		
		if(t == 15) {
			output.append("\t\tPreference : " + Integer.parseInt(data[0] + data[1], 16) +"\n");
			output.append("\t\tMail Exchange : ");
			output.append(decodeName(data, 2));
			output.append("\n");
		}
		
		if (t == 16) {
			output.append("\t\tTXT Length : " + Integer.parseInt(data[0], 16) +"\n");
			output.append("\t\tTXT : ");
			for(int j = 1; j < data.length; j++) {
				int str = Integer.parseInt(data[j], 16);
				output.append((char)str);
			}
		}
		
		/*if(t == 33) {
			output.append("\t\tPriority : " + Integer.parseInt(data[0] + data[1], 16) +"\n");
			output.append("\t\tWeight : "+ Integer.parseInt(data[2] + data[3], 16) +"\n");
			output.append("\t\tPort : "+ Integer.parseInt(data[4] + data[5], 16) +"\n");
			output.append("\t\tTarget : ");
			output.append(decodeName(data, 6));
			output.append("\n");
		}*/
		
		
		
		
		return output.toString();
	}
	
	
	public String getType(String type) {
		int t =Integer.parseInt(type, 16);
		if (t == 1) {
			return "A (Host Adress) (1)";
		}
		if(t == 2) {
			return "NS (2)";
		}
		
		if(t == 3) {
			return "MD (3)";
		}
		
		if(t == 4) {
			return "MF (4)";
		}
		
		if(t == 5) {
			return "CNAME (5)";
		}
		
		if(t == 6) {
			return "SOA (6)";
		}
		
		if(t == 7) {
			return "MB (7)";
		}
		
		if(t == 8) {
			return "MG (8)";
		}
		
		if(t == 9) {
			return "MR (9)";
		}
		
		if(t == 10) {
			return "NULL (10)";
		}
		
		if(t == 11) {
			return "WKS (11)";
		}
		
		if(t == 12) {
			return "PTR (12)";
		}
		
		if(t == 13) {
			return "HINFO (13)";
		}
		
		if(t == 14) {
			return "MINFO (14)";
		}
		
		if(t == 15) {
			return "MX (15)";
		}
		
		if(t == 16) {
			return "TXT (16)";
		}
		
		if(t == 28) {
			return "AAAA (28)";
		}
		
		if(t == 29) {
			return "LOC (29)";
		}
		
		if(t == 33) {
			return "SRV (33)";
		}
		return t + " (Unknown)";

	}
	
	public String getClasse(String classe) {
		int c =Integer.parseInt(classe, 16);
		if(c == 1) {
			return "IN (Internet) (0x0001)";
		}
		
		if(c == 2) {
			return "CS (Class Csnet) (0x0002)";
		}
		
		if(c == 3) {
			return "CH (Chaos) (0x0003)";
		}
		
		if(c == 4) {
			return "HS (Hesiod) (0x0004)";
		}
		return "Unknown";
	}
	
	public static String toString(String[] tab) {
		StringBuilder output = new StringBuilder();
		for(String s : tab) {
			output.append(s);
		}
		return output.toString();
	}
	
	public static String[] toStringTab(List<String> ls) {
		String[] output = new String[ls.size()];
		for(int i = 0; i < ls.size(); i++) {
			output[i] = ls.get(i);
		}
		return output;
	}
	
	
	
	@Override
	public String analyze() {
		StringBuilder output = new StringBuilder();
		output.append("Domain Name System\n");
		p_sections = 0;
		output.append("\tTransaction ID : 0x" + getIdHex() +"\n");
		output.append(getFlagsFormat());
		output.append(getNbQuestionsFormat());
		output.append(getNbAnswerRRFormat());
		output.append(getNbAuthorityRRFormat());
		output.append(getNbAdditionnalRRFormat());
		
		
		int nbQ = Integer.parseInt(getNbQuestions(), 16);
		int num_q = 0;
		while(nbQ > 0) {
			num_q++;
			output.append("\tQuery " + num_q + " : \n");
			output.append(getQuestionsFormat(getQuestionSection()));
			nbQ--;
		}
		
		int nbAns = Integer.parseInt(getNbAnswerRR(), 16);
		int num_ans = 0;
		while(nbAns > 0) {
			num_ans++;
			output.append("\tAnswer " + num_ans + " : \n");
			output.append(getRRFormat(getOtherSectionsRR()));
			nbAns--;
		}

		
		int nbAut = Integer.parseInt(getNbAuthorityRR(), 16);
		int num_aut = 0;
		while(nbAut > 0) {
			num_aut++;
			output.append("\tAuthority " + num_aut + " : \n");
			output.append(getRRFormat(getOtherSectionsRR()));
			nbAut--;
		}
		
		int nbAdd = Integer.parseInt(getNbAdditionnalRR(), 16);
		int num_add = 0;
		while(nbAdd > 0) {
			num_add++;
			output.append("\tAdditionnal " + num_add + " : \n");
			output.append(getRRFormat(getOtherSectionsRR()));
			nbAdd--;
		}
		return output.toString();
	}

	
	 private static String hexToBin(String hex){
	        hex = hex.replaceAll("0", "0000");
	        hex = hex.replaceAll("1", "0001");
	        hex = hex.replaceAll("2", "0010");
	        hex = hex.replaceAll("3", "0011");
	        hex = hex.replaceAll("4", "0100");
	        hex = hex.replaceAll("5", "0101");
	        hex = hex.replaceAll("6", "0110");
	        hex = hex.replaceAll("7", "0111");
	        hex = hex.replaceAll("8", "1000");
	        hex = hex.replaceAll("9", "1001");
	        hex = hex.replaceAll("A", "1010");
	        hex = hex.replaceAll("B", "1011");
	        hex = hex.replaceAll("C", "1100");
	        hex = hex.replaceAll("D", "1101");
	        hex = hex.replaceAll("E", "1110");
	        hex = hex.replaceAll("F", "1111");
	        hex = hex.replaceAll("a", "1010");
	        hex = hex.replaceAll("b", "1011");
	        hex = hex.replaceAll("c", "1100");
	        hex = hex.replaceAll("d", "1101");
	        hex = hex.replaceAll("e", "1110");
	        hex = hex.replaceAll("f", "1111");
	        return hex;
	    }
}

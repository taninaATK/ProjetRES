package champs;

import java.util.List;

public class HeaderCheck {
	private boolean check = false; //verifie si le checksum est correcte (initialement faux)
	private String[] checksum; // checksum
	private String[] header; //tableau contenant l'ent�te ip
	
	public HeaderCheck(String[] checksum, String[] header) {
		this.checksum = checksum;
		this.header = header;
		//this.verifieChecksum();
	}
	
	public String verifieChecksum() {
		int sum = 0; //somme de tous les octets
		for(int i=0; i<header.length - 1; i+=2) { //boucle sur chaque octet
			//octet en chaine binaire
			String octetBin = hexToBin(header[i] + header[i+1]);
			//on somme tous les octets
			sum += Integer.parseInt(octetBin, 2);
		}
		
		String res = Integer.toBinaryString(sum);
		//on r�cup�re les retenues
		int retenue = Integer.parseInt(res.substring(0, res.length()-16),2);
		//on recupere la somme sans les retenues
		sum = Integer.parseInt(res.substring(res.length()-16, res.length()),2);
		//on ajoute les retenues � la somme
		sum += retenue;
		
		//si sum == "ffff" alors il n'y a pas d'erreur
		if (Integer.toHexString(sum).equals("ffff")){
			check = true;
		}
		
		else {
			check = false;
		}
		return Integer.toHexString(sum);
	}
	
	public boolean getCheck() {
		return check;
	}
	
	public String getChecksum() {
		return checksum[0]+checksum[1];
	}
	
	public String[] getHeader() {
		return header;
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



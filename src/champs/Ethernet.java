package champs;
/**
 * Classe repr�sentant un ent�te Ethernet
 * @author manelle
 *
 */
public class Ethernet {
	private String macSource[];	//adresse mac source 
	private String macDest[]; //adresse mac destination
	private String type[];	//type 
	
	public Ethernet(String macSource[], String macDest[], String type[]) {
		this.macSource = macSource;
		this.macDest = macDest;
		this.type = type;
	}
	
	public String[] getMacSource() {
		return macSource;
	}
	
	public String[] getMacDest() {
		return macDest;
	}
	
	public String[] getType() {
		return type;
	}
	
	//Pour pouvoir analyser le type
	public String getTypeFused() {
		StringBuilder sb = new StringBuilder();
		for(String s : type) {
			sb.append(s);
		}
		
		return sb.toString();
	}
	
	public String toString() {
		String source = macSource[0] + ":" + macSource[1] + ":" + macSource[2] + ":" + macSource[3] + ":" + macSource[4] + ":" + macSource[5];
		String dest = macDest[0] + ":" + macDest[1] + ":" + macDest[2] + ":" + macDest[3] + ":" + macDest[4] + ":" + macDest[5];
		String typehex = "0x" + this.type[0] + this.type[1];
		
		StringBuilder ethernet = new StringBuilder();
		ethernet.append("Ethernet\n\tDestination: " + dest);
		if(dest.equals("ff:ff:ff:ff:ff:ff") || dest.equals("FF:FF:FF:FF:FF:FF")) {
			ethernet.append(" (Broadcast)");
		}
		String subLayer;
		ethernet.append("\n\tSource: " + source + "\n\tType: ");
		if(type[0].equals("08") && type[1].equals("06")) {
			ethernet.append("ARP ");
		}
		if(type[0].equals("08") && type[1].equals("00")) {
			ethernet.append("IPv4 ");
		}
		
		ethernet.append("(" + typehex +")\n");
		
		return ethernet.toString();
	}
}

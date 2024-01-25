package TraceAnalyzer;

import champs.*;
import java.io.File;
import java.io.FileWriter;
import java.time.format.DateTimeFormatter;
import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

/** Classe permettant de charger une trace depuis un fichier et sauvegarder une analyze de celle-ci
 * @author tanina
 *
 */
public class TraceManager {
	
	public static String load(String path) throws Exception{
		try {
			//Initialisation des variables permetant d'ouvrir le fichier, le parcourir et stocker les octets de la trace
			//sans l'offset (etc...) dans un String
			File file = new File(path);
			BufferedReader br = new BufferedReader(new FileReader(file));
			List<Trace> output = new ArrayList<Trace>(); //Stocker les traces contenues dans le fichier
			int line_count = 0; //Compteur de lignes par trace
			int line_file = 0;
			int byte_count = 0; //Compteur du nombre d'octet par trace
			String line; //pour parcourir les lignes
			Trace erreur = null;
			boolean last_line = false; //Pour vérifier si le format de la trace est bien en matrice
			
			//Pour initialiser chaque champ de chaque Trace
			List<List<String>> trace = new ArrayList<List<String>>();
			
			
			while((line = br.readLine()) != null) {
				line_count++;
				line_file++;
				
				//On récupère le contenu de la ligne
				String[] contenu = line.split(" ");
				
				//Est-ce qu'on commence par un nombre hexa (offset) ?
				if(isHex(contenu[0])) {
					List<String> current_line = new ArrayList<>();
					
					//Cas d'une nouvelle trace : pas la première ligne && offset == 0
					int check = Integer.parseInt(contenu[0], 16);
					if(line_file > 1 && check == 0) {
						//on sauvegarde la trace précédente
						if(erreur != null) {
							output.add(erreur);
							erreur = null;
						} else {
							output.add(getTrace(trace));
						}
						trace.clear();
						byte_count = 0;
						line_count = 1;
						last_line = false;
					}
					
					//Offset correct ?
					if(byte_count == check && (!last_line)) {
						//On récupère chaque octet de la ligne
						for(int k = 1; k < contenu.length && erreur == null; k++) {
							if(!contenu[k].equals(" ") && isHex(contenu[k])) {
								//Cas où on a pas un octet = break
								if(contenu[k].length() != 2) {
									break;
								}
								//Sinon on prend l'octet
								current_line.add(contenu[k]);
								byte_count++;
							}
						}
						//Derniere ligne de la trace
						if(trace.size() > 0) {
							if(byte_count-check < trace.get(trace.size()-1).size()) {
								last_line = true;
							}
						}
						trace.add(current_line);		
					} else {
						erreur = new Trace(line_count);
						line_count = 1;
					}				
				}
				
			}
			//Ajout de la dernière trace
			if(erreur == null ) {
				output.add(getTrace(trace));
			} else {
				output.add(erreur);
			}
			
			//On referme le fichier
			br.close();
			
			//Pour chaque trace, on l'analyse
			int count = 0;
			//Pour la sauvegarde dans un fichier .txt
			StringBuilder sb = new StringBuilder();
			for(Trace t : output) {
				count ++;
				sb.append("Trace N°" + count + "\n");
				System.out.println("Trace N°" + count);
				sb.append(t.analyze());
				sb.append("\n");
				System.out.println();
			}
			
			return sb.toString();
			
		} catch(Exception e) {
			System.out.println("Erreur lors de la lecture du fichier, veuillez relancer l'analyse.");
		}
		return "Erreur";
	} 

	public static Trace getTrace(List<List<String>> ls) {
		List<String> liste = new ArrayList<>();
		
		//On veut d'abord le champ ethernet
		//Pour chaque ligne de la trace
		for(int i = 0; i < ls.size() && liste.size() < 14;) {
			//Pour chaque octet de la ligne
			for(int j = 0; j < ls.get(i).size() && liste.size() < 14;) {
				//System.out.println(ls.get(i).get(j));
				liste.add(ls.get(i).get(j));
				ls.get(i).remove(ls.get(i).get(j)); //On supprime au fur et à mesure les octets pris en compte
			}
		}
		
		String[] destmac = toStringTab(liste.subList(0, 6));
		String[] srcmac = toStringTab(liste.subList(6, 12));
		String[] type = toStringTab(liste.subList(12, 14));
		
		Ethernet e = new Ethernet(srcmac, destmac, type);
		List<Champs> c = new ArrayList<>();
		//System.out.println(e.getTypeFused());
		
		liste.clear();
		
		//Cas msg ARP
		if((e.getTypeFused().equals("0806")) || (e.getTypeFused().equals("8035"))) {
			for(int i = 0; i < ls.size() && liste.size() < 28; i++) {
				//Pour chaque octet de la ligne
				for(int j = 0; j < ls.get(i).size() && liste.size() < 28;) {
					//System.out.println(ls.get(i).get(j));
					liste.add(ls.get(i).get(j));
					ls.get(i).remove(ls.get(i).get(j)); //On supprime au fur et à mesure les octets pris en compte
				}
				//System.out.println();
			}
			//Génération du message ARP
			String[] h = toStringTab(liste.subList(0, 2));
	
			String[] protocol = toStringTab(liste.subList(2, 4));
			
			String[] hlen = toStringTab(liste.subList(4, 5));
			
			String[] plen = toStringTab(liste.subList(5, 6));

			String[] operation = toStringTab(liste.subList(6, 8));
			
			String[] sha = toStringTab(liste.subList(8, 14));
			
			String[] sia = toStringTab(liste.subList(14, 18));
			
			String[] tha = toStringTab(liste.subList(18, 24));
			
			String tia[] = toStringTab(liste.subList(24, 28));
			
			ARP msg = new ARP(h, protocol, hlen, plen, operation, sha, sia, tha, tia);
			c.add(msg);
			
			return new Trace(e, c);
		}
		
		//Cas En tete IP
		if(e.getTypeFused().equals("0800")) {
			for(int i = 0; i < ls.size(); i++) {
				//Pour chaque octet de la ligne
				for(int j = 0; j < ls.get(i).size();) {
					//System.out.println(ls.get(i).get(j));
					liste.add(ls.get(i).get(j));
					ls.get(i).remove(ls.get(i).get(j)); //On supprime au fur et à mesure les octets pris en compte
				}
				//System.out.println();
			}
			
			//G�n�ration du message IP
			
			//r�cup�ration du champs version+ihl
			List<String> l = liste.subList(0,1);
			String version_ihl = l.get(0);
			
			//r�cup�ration de version et ihl s�par�ment
			String version = version_ihl.substring(0,1);
			String ihl = version_ihl.substring(1,2);
			
			//r�cup�ration su champs tos
			String tos = liste.subList(1, 2).get(0);
			
			//recup�ration du champs total length
			String[] total_length = toStringTab(liste.subList(2, 4));
			
			//r�cup�ration du champs Identification
			String[] id = toStringTab(liste.subList(4, 6));
			
			//r�cup�ration du champs flags + fragment offset
			String[] flag_off = toStringTab(liste.subList(6, 8));
			
			//r�cup�ration du champs TTL
			String ttl = liste.subList(8, 9).get(0);
			
			//r�cup�ration du champs protocol
			String proto = liste.subList(9, 10).get(0);
			
			//r�cup�ration du champs Header checksum
			String[] checksum = toStringTab(liste.subList(10, 12));
			String[] liste_tab = toStringTab(liste);
			HeaderCheck check = new HeaderCheck(checksum, liste_tab);
			
			//r�cup�ration du champs Ip source
			String[] sourceIP = toStringTab(liste.subList(12, 16));
			
			//r�cup�ration du champs Ip destination
			String[] destIP = toStringTab(liste.subList(16, 20));
			
			//r�cup�ration du champs options
			int opt_length = Integer.parseInt(ihl)*4 - 20;
			String[] options = toStringTab(liste.subList(20, 20 + opt_length));
			
			//Suppression des octets de l'en-tête IP
			int suppr = 0;
			for(int i = 0; i < liste.size() && suppr < opt_length + 20; suppr++) {
					liste.remove(liste.get(i));
			}
			
			Ip msgIP = new Ip(version, ihl, tos, total_length, id, flag_off, ttl, proto, check, sourceIP, destIP, options);
			c.add(msgIP);
			
			//Si on a un msg UDP, on doit fournir son analyse, les octets sont dans la variable liste
			if(msgIP.getProtocolName().equals("UDP")){
				//System.out.println("ok");
				//liste contient le reste de la trace, ls2 rien : liste va transferer ses octets à ls2
				List<String> ls2 = new ArrayList<String>();
				
				//Récupération de l'en-tête UDP de longueur fixe (8 octets)
				for(int i = 0; i<liste.size() && ls2.size() < 8;) {
					String s = liste.get(i);
					ls2.add(s); //on copie l'octet dans liste
					liste.remove(s); //On le supprime de ls
				}
				
				//Recuperation des différents champs
				String src = toString(toStringTab(ls2.subList(0, 2)));
				String dest = toString(toStringTab(ls2.subList(2, 4)));
				String length = toString(toStringTab(ls2.subList(4, 6)));
				String[] checksumUDP = toStringTab(ls2.subList(6, 8));
				
				UDP udpHeader = new UDP(src, dest, length, checksumUDP);
				c.add(udpHeader);
				
				if(src.equals("0043") || src.equals("0044")) {
					String opCode = toString(toStringTab(liste.subList(0, 1)));
					String htype = toString(toStringTab(liste.subList(1, 2)));
					String hlen = toString(toStringTab(liste.subList(2, 3)));
					String hops = toString(toStringTab(liste.subList(3, 4)));
					String transID = toString(toStringTab(liste.subList(4, 8)));
					String seconds = toString(toStringTab(liste.subList(8, 10)));
					String flags = toString(toStringTab(liste.subList(10, 12)));
					String[] clientIP = toStringTab(liste.subList(12, 16));
					String[] yourIP = toStringTab(liste.subList(16, 20));
					String[] serverIP = toStringTab(liste.subList(20, 24));
					String[] gatewayIP = toStringTab(liste.subList(24, 28));
					String[] clientHW = toStringTab(liste.subList(28, 44));
					String[] serverName = toStringTab(liste.subList(44, 108));
					String[] bootfile = toStringTab(liste.subList(108, 236));
					String mCookie = toString(toStringTab(liste.subList(236, 240)));
				
					//Création des options
					ls2.clear();
					//On conserve les octets d'options dans liste
					liste = liste.subList(240, liste.size());
					List<String[]> optionList = new ArrayList<>();
					//Pour chaque octet d'option qui reste dans la trace
					for(int j = 0; j < liste.size();) {
						int optLength = 0;
						int check1 = Integer.parseInt(liste.get(0), 16);
						switch (check1){
							case 0 :
								optLength = liste.size();
								break;
								
							case 255 :
								//Pour ajouter l'octet de l'option
								optLength = 1;
								break;
								
							case 80 :
								//Pour ajouter l'octet de l'option
								optLength = 1;
								break;
								
							default :
								//pour ajouter l'octet d'option + length + valeur de l'option
								optLength = Integer.parseInt(liste.get(1), 16) + 2;
						}
						optionList.add(toStringTab(liste.subList(0, optLength)));
						liste = liste.subList(optLength, liste.size());
						
					}
					
					
					DHCP msgDHCP = new DHCP(opCode, htype, hlen, hops, transID, seconds,
									flags, clientIP, yourIP, serverIP, gatewayIP, clientHW,
									serverName, bootfile, mCookie, optionList);
					
					c.add(msgDHCP);
					//System.out.println(msgDHCP.analyze());
				}
				
				if(src.equals("0035") || dest.equals("0035")) { //port dns (=53)
					//System.out.println("ok");
					String[] dns = toStringTab(liste);
					String[] dnsId = toStringTab(liste.subList(0, 2));
					String[] flags = toStringTab(liste.subList(2, 4));
					String[] nb_q = toStringTab(liste.subList(4, 6));
					String[] nb_ans = toStringTab(liste.subList(6, 8));
					String[] nb_aut = toStringTab(liste.subList(8, 10));
					String[] nb_add = toStringTab(liste.subList(10, 12));
					String[] sections = toStringTab(liste.subList(12, liste.size()));
					
					DNS msgDNS = new DNS(dns, dnsId, flags, nb_q, nb_ans, nb_aut, nb_add, sections);
					c.add(msgDNS);
					//System.out.println(msgDNS.analyze());
				}
			}
			
			//System.out.println(msgIP.analyze());
			return new Trace(e,c);			
		}
		
		return null;
	}
	
	private static boolean isHex(String s) {
		try {
			Integer.parseInt(s, 16);
			return true;
		} catch(Exception exception){
			return false;
		}
	}

	public static boolean save(String path, String s) {
		//Nom du fichier = date et heure de l'analyse
		String filename = DateTimeFormatter.ofPattern("yyyy_MM_dd_HH_mm_ss").format(java.time.LocalDateTime.now());
		//System.out.println(filename);
		String filepath = path + filename + ".txt";
		//Partie de création de la save
		File save = new File(filepath);
		try {
			if(save.createNewFile()) {
				FileWriter fwriter = new FileWriter(filepath);
				fwriter.write(s);
				fwriter.close();
				System.out.println("Sauvegarde effectuée.");
			} else {
				System.out.println("Erreur lors de la sauvegarde de l'analyse");
			}
		} catch(Exception e) {
			System.out.println(e.getMessage());
		}
		
		
		return false;
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

}

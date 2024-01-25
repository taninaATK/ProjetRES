package TraceAnalyzer;
import java.util.ArrayList;
import java.util.List;

import champs.*; //on importe les classes correspondants aux champs

/** Classe permettant de représenter une trace
 * @author tanina
 *
 */
public class Trace {
	private Ethernet ethernet;
	private List<Champs> message = new ArrayList<Champs>();
	private Integer error = null;
	
	public Trace(Ethernet e, List<Champs> m) {
		ethernet = e; message = m;
	}
	
	public Trace(int e) {
		error = e;
	}
	
	public String analyze() {
		StringBuilder output = new StringBuilder();
		if(error == null) {
			output.append(ethernet.toString());
			for(Champs c : message){
				output.append(c.analyze());
			}
			String s = output.toString();
			System.out.println(s);
			return s;
		} else {
			output.append("Trace en erreur à la ligne : " + error.toString());
			output.append(" de la trace (la première ligne étant numérotée par 1).\n");
			String s = output.toString();
			System.out.println(s);
			return s;
		}
	}
}

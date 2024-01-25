package TraceAnalyzer;

public class TraceTest {

	public static void main(String[] args) {
		try {
			String s = TraceManager.load("/home/tanina/cours/projet reseaux/arp.txt");
			String path = "/home/tanina/cours/projet reseaux/";
			TraceManager.save(path, s);
			
		} catch (Exception e){
			System.out.println(e.getMessage());
		}
	}
}

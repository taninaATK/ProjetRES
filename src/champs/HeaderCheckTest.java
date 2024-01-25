package champs;

public class HeaderCheckTest {
	public static void main(String[] args) {
		String[] checksum = {"69", "8d"};
		String[] header = {"45", "00", "00", "48", "49", "ba", "00", "00", "1e", "06", "69", "8d", "c1", "37", "33", "f6", "c1", "37", "33", "04"};
		HeaderCheck h = new HeaderCheck(checksum, header);
		System.out.println(h.verifieChecksum());
		System.out.println("check = "+h.getCheck());
		
	}
}

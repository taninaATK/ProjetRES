package TraceAnalyzer;

import java.util.Scanner;

public class Main {
	public static void main(String[] args) {
		Scanner sc = new Scanner(System.in);
		System.out.println("Veuillez entrez le chemin absolu vers le fichier à analyser");
		String filepath = sc.nextLine();
		System.out.println("Veuillez entrez le chemin absolu vers le dossier dans lequel vous voulez stocker les sauvegardes");
		System.out.println("Format du chemin : .../.../.../ (le chemin doit obligatoirement se terminer par un '/'");
		String savepath = sc.nextLine();
		if(((savepath.charAt(savepath.length()-1) != '/')) ||
				(!(filepath.substring(filepath.length()-4, filepath.length()).equals(".txt")))) {
			System.out.println("Veuillez saisir des chemins corrects et relancer l'analyse.");
		} else {
			try {
			TraceManager.save(savepath, TraceManager.load(filepath));
			} catch (Exception e){
				System.out.println();
				System.out.println("Le format des chemins que vous avez donnés pour le fichier trace et/ou "
						+ "\nle dossier de sauvegarde semble être incorrect. Veuillez respecter le format requis et relancer l'application");
			} finally {
				sc.close();
			}	
		}
	}

}

Structure du code :

	Package TraceAnalyzer :
		- Main : contient le Main qui va lancer le programme
		- TraceManager : fonctions de lecture de fichier + génération des trames + sauvegarde de l'analyse
		- TraceTest : pour tester
		- Trace : classe pour représenter les trames en tant qu'objet + fonction d'analyse
		
	Package champs :
		- Champs : Interface des protocoles encapsulé, impose la fonction analyse()
		- Autres classes : tous les protocoles, avec des accesseurs, constructeurs + fonction d'analyse

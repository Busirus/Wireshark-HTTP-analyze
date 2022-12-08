# Importe les bibliothèques nécessaires
from scapy.all import *
import dpkt, csv

# Demande le nom du fichier PCAP à analyser
pcap_file = input("Entrez le nom du fichier PCAP à analyser : ")

# Nom du fichier CSV où enregistrer les identifiants et les mots de passe
csv_file = "credentials.csv"

# Ouvre le fichier CSV en mode écriture
with open(csv_file, "w", newline="") as f:
  # Initialise l'écrivain CSV
  writer = csv.writer(f)

  # Écrit les en-têtes des colonnes dans le fichier CSV
  writer.writerow(["Identifiant", "Mot de passe"])

  # Ouvre le fichier PCAP en mode lecture
  with open(pcap_file, "rb") as f:
    # Parse le fichier PCAP
    pcap = dpkt.pcap.Reader(f)

    # Parcoure chaque paquet dans le fichier PCAP
    for ts, buf in pcap:
      # Convertit le tampon binaire en paquet Scapy
      packet = Ether(buf)

      # Vérifie si le paquet contient un segment TCP
      if TCP in packet:
        # Récupère le segment TCP du paquet
        tcp = packet[TCP]

        # Vérifie si le segment TCP contient des données HTTP
        if Raw in tcp and tcp.dport == 80:
        # Récupère les données HTTP du segment TCP
            http = tcp[Raw].load

        # Vérifie si les données HTTP contiennent des identifiants ou des mots de passe
        if "username" in http or "password" in http:
            # Récupère l'identifiant et le mot de passe contenus dans les données HTTP
            username = http.split("username=")[1].split("&")[0]
            password = http.split("password=")[1].split("&")[0]

            # Écrit l'identifiant et le mot de passe dans le fichier CSV
            writer.writerow([username, password])

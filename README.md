# 📡 Multicast Analyzer

Ce script Python analyse les trames multicast contenues dans un fichier `.pcap` à l’aide de **Scapy**.

## 🔧 Dépendances

Installez Scapy avec pip :

```bash
pip install scapy
```

## 🚀 Utilisation

Lancez le script avec un fichier `.pcap` en argument :

```bash
python analyze_multicast.py fichier.pcap
```

## 🔍 Exemple de sortie

```
Analyse du fichier : capture.pcap

⏭️ Paquets ignorés : 0

📊 Top 10 sources multicast :
01:00:5e:00:00:fb : 120 paquets
...

🔎 Protocoles IP multicast (par numéro de protocole) :
Proto 17 : 95 paquets
Proto 2  : 25 paquets
```

## 📂 Fonctionnalités

- Détection des adresses MAC multicast
- Comptage des sources multicast
- Identification des protocoles IP associés (par numéro)

## 📜 Licence

MIT

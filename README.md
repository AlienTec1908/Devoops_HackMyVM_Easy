# Devoops - HackMyVM (Medium)
 
![Devoops.png](Devoops.png)

## Übersicht

*   **VM:** Devoops
*   **Plattform:** ([https://hackmyvm.eu/machines/machine.php?vm=Devoops](https://hackmyvm.eu/machines/machine.php?vm=Devoops))
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 29. Mai 2025
*   **Original-Writeup:** [https://alientec1908.github.io/Devoops_HackMyVM_Easy/](https://alientec1908.github.io/Devoops_HackMyVM_Easy/)
*   **Autor:** Ben C.

## Kurzbeschreibung

Die "Devoops"-Maschine von HackMyVM ist eine Linux-VM mit mittlerem Schwierigkeitsgrad. Ziel ist es, Root-Zugriff zu erlangen. Der Lösungsweg beinhaltet die Ausnutzung einer Arbitrary File Read Schwachstelle in einem Vite.js Development Server, um an ein JWT-Secret zu gelangen. Mit diesem Secret wird ein Admin-JWT erstellt, um Remote Code Execution zu erlangen. Die Rechteausweitung erfolgt über die Analyse eines Git-Repositories (Leak eines SSH-Keys für den Benutzer "hana") und anschließend über eine fehlerhafte Sudo-Konfiguration, die es erlaubt, den `arp`-Befehl zum Auslesen der `/etc/shadow`-Datei zu missbrauchen, um schließlich das Root-Passwort zu knacken.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `nikto`
*   `curl`
*   `jwt_tool` (impliziert durch die Notwendigkeit, JWTs zu bearbeiten, auch wenn `jwt.io` im Bericht genutzt wurde)
*   `python3` (für URL-Encoding und HTTP-Server)
*   `nc` (netcat)
*   `jq`
*   `chisel`
*   `ssh`
*   `hydra`
*   `git`
*   `sed`
*   `john` (John the Ripper)
*   Standard Linux-Befehle (`vi`, `ls`, `cat`, `find`, `chmod`, `echo`, `sudo`, `awk`, `busybox`, `netstat`, `wget`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Devoops" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Enumeration:**
    *   IP-Findung mittels `arp-scan` (192.168.2.205).
    *   Umfassender Portscan mit `nmap` identifizierte Port 3000 (HTTP, Vite.js Development Server).
    *   Analyse der Nmap-Scripts und HTTP-Header wies auf Vite.js und eine `server.allowedHosts`-Konfiguration hin.
    *   `nikto` fand keine kritischen direkten Schwachstellen, aber Hinweise auf fehlende Security Header.

2.  **Schwachstellensuche & Quellcode-Analyse:**
    *   Zugriff auf `http://192.168.2.205:3000/server.js` offenbarte den Quellcode der Node.js-Anwendung, inkl. der Logik für JWT-Authentifizierung (`/api/sign`, `/api/execute`) und einen `COMMAND_FILTER`.
    *   OSINT-Recherche zu Vite.js führte zur Identifizierung einer (fiktiven) Arbitrary File Read Schwachstelle (CVE-2025-31125).

3.  **Initial Access (Arbitrary File Read & RCE):**
    *   Ausnutzung der Vite.js Arbitrary File Read (`/.env?raw??`) zum Auslesen der `.env`-Datei, welche das `JWT_SECRET` (`2942szKG7Ev83aDviugAa6rFpKixZzZz`) und den `COMMAND_FILTER` enthielt.
    *   Erstellung eines Admin-JWTs (mit `role: "admin"`) unter Verwendung des geleakten Secrets (z.B. via jwt.io).
    *   Umgehung des `COMMAND_FILTER` durch Verwendung von `n\c` (statt `nc`) und korrekt URL-kodiertem Payload, um eine Reverse Shell via `/execute`-Endpunkt zu erhalten.
    *   Zugriff als Benutzer `runner`.

4.  **Post-Exploitation / Privilege Escalation (von `runner` zu `hana`):**
    *   Enumeration als `runner`: Entdeckung lokal laufender Dienste (SSH auf Port 22, Gitea auf Port 3002 – beide nur localhost).
    *   Upload von `chisel` auf das Zielsystem und Aufbau von Reverse Port Forwarding Tunnels, um auf Gitea (`localhost:9090` auf Kali) und SSH (`localhost:2222` auf Kali) zugreifen zu können.
    *   Analyse der Gitea-Instanz: Entdeckung eines Git-Repositories (`node.git`) des Benutzers `hana` im Verzeichnis `/opt/gitea/git/hana/`.
    *   Übertragung des `node.git`-Repository auf die Angreifer-Maschine.
    *   Analyse der Git-Historie (`git log`): Ein verdächtiger Commit ("del: oops!") wurde gefunden.
    *   `git diff` zwischen den Commits offenbarte einen zuvor committeten und dann gelöschten privaten SSH-Key (`id_ed25519`) für den Benutzer `hana`.
    *   Korrektur des SSH-Key-Formats (Entfernung von Diff-Artefakten) und erfolgreicher SSH-Login als `hana`.

5.  **Privilege Escalation (von `hana` zu root):**
    *   Als `hana` wurde mittels `sudo -l` festgestellt, dass `/sbin/arp` ohne Passwort als `root` ausgeführt werden darf.
    *   Ausnutzung dieser `sudo`-Regel: `sudo /sbin/arp -v -f "/etc/shadow"` ermöglichte das Auslesen der `/etc/shadow`-Datei, da `arp` bei Formatfehlern die Zeileninhalte ausgibt.
    *   Der Passwort-Hash für den `root`-Benutzer wurde extrahiert.
    *   Knacken des Root-Passwort-Hashes mit `john` und `rockyou.txt`. Das Passwort wurde als `eris` identifiziert.
    *   Erfolgreicher Wechsel zum `root`-Benutzer mittels `su root` und dem geknackten Passwort.

## Wichtige Schwachstellen und Konzepte

*   **Arbitrary File Read in Vite.js (CVE-2025-31125):** Ermöglichte das Auslesen der `.env`-Datei und somit des `JWT_SECRET`. Ausgenutzt durch Anhängen von `?raw??` an den Dateinamen in der URL.
*   **JWT Secret Leak / Insecure JWT Implementation:** Das geleakte `JWT_SECRET` erlaubte die Erstellung beliebiger gültiger JWTs, einschließlich solcher mit Admin-Rechten.
*   **Command Injection Filter Bypass:** Ein unzureichender `COMMAND_FILTER` konnte durch leichte Obfuskation (`n\c` statt `nc`) und korrekte URL-Kodierung umgangen werden, um eine Reverse Shell zu erlangen.
*   **Sensitive Data in Git History (SSH Key Leak):** Ein privater SSH-Key wurde versehentlich in ein Git-Repository committet und war trotz späterem Löschen noch in der Historie auffindbar.
*   **Sudo Misconfiguration (arp):** Die `sudoers`-Regel erlaubte dem Benutzer `hana`, `/sbin/arp` als `root` auszuführen. Die `-f`-Option von `arp` wurde missbraucht, um beliebige Dateien (hier `/etc/shadow`) zu lesen.
*   **Weak Password (root):** Das Passwort des `root`-Benutzers (`eris`) war in der `rockyou.txt`-Liste enthalten und konnte leicht geknackt werden.
*   **Port Forwarding / Tunneling:** `chisel` wurde verwendet, um auf Dienste zuzugreifen, die nur auf dem Loopback-Interface des Zielsystems lauschten.

## Flags

*   **User Flag (`/home/hana/user.flag`):** `flag{03d0e150ae9fc686a827b41e1969d497}`
*   **Root Flag (`/root/R007.7x7oOoOoOoOoOoO`):** `flag{a834296543f4c2990909ce1c56becfba}`

## Tags

`HackMyVM`, `Devoops`, `Medium`, `Linux`, `Web`, `ViteJS`, `JWT`, `Arbitrary File Read`, `Command Injection`, `Git Leak`, `SSH Key Leak`, `Sudo Exploit`, `Password Cracking`, `Privilege Escalation`, `Chisel`

# Glutton
### Anàlisi d'una bústia d'anti-phishing

Glutton llegeix periòdicament (per defecte cada 10 segons) d'una bústia de Gmail buscant els correus no llegits. Els descarrega, els analitza i decideix si aquell correu pot ser phishing (carpeta PHISHING), si conté adjunts (carpeta ADJUNTS) o si és correu brossa o mal ús (els marca com a llegits).

L'anàlisi es duu a terme a VirusTotal, Blue Coat Sitereview i Google Safe Browsing.

### ATENCIÓ

Aquest programa ha estat testejat amb el sistema operatiu Linux, distribució *Ubuntu 18.04 desktop amd64*.

### Instruccions d'instal·lació

Primer de tot és necessari crear-se un compte de Gmail i vincular-la a la Consola de Desenvolupadors de Google. S'ha de descarregar el fitxer ```client_secret.json```, nombrar-lo així i guardar-lo al mateix directori del programa. Quan s'executi per primer cop, s'obrirà el navegador automàticament per acceptar les condicions i crear-se així l'arxiu ```credentials.json```, necessari pel bon funcionament del programa.

Posteriorment s'han d'instal·lar les següents dependències en cas que no estiguin instal·lades:

```
sudo apt install python
sudo apt install python-pip
sudo pip install --upgrade google-api-python-client
sudo pip install --upgrade oauth2client
sudo pip install requests
```

Cal modificar el codi als arxius ```virustotal.py``` i ```safebrowsing.py``` i introduir una API_KEY vàlida (es poden aconseguir gratuïtament creant un compte a Google i a VirusTotal.

### Execució

Per executar les opcions per defecte:
```python glutton.py```

Altres execucions possibles:
```
python glutton.py no-redirects   # Per no buscar redireccions
python glutton.py . complet      # Anàlisi complet
python glutton.py no-redirects complet   # Les dues opcions anteriors alhora
```

### Referència

Aquest software ha estat desenvolupat com a part d'un Treball de Final de Grau, de Xavi Gombau. 

Treball complet: *DISPONIBLE PROPERAMENT*

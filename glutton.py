# -*- coding: latin-1 -*-
"""
         (                             )      ) 
 (       )\ )         *   )  *   )  ( /(   ( /( 
 )\ )   (()/(    (  ` )  /(` )  /(  )\())  )\())
(()/(    /(_))   )\  ( )(_))( )(_))((_)\  ((_)\ 
 /(_))_ (_))  _ ((_)(_(_())(_(_())   ((_)  _((_)
(_)) __|| |  | | | ||_   _||_   _|  / _ \ | \| |
  | (_ || |__| |_| |  | |    | |   | (_) || .` |
   \___||____|\___/   |_|    |_|    \___/ |_|\_|

Designed and created by: XAVIER GOMBAU
GitHub: LyokoGP

"""

from __future__ import print_function
from apiclient.discovery import build
from apiclient import errors
from httplib2 import Http
from oauth2client import file, client, tools
import httplib2
import base64
import email
import re
import virustotal, bluecoat, redirects, safebrowsing
import colors
import time
import banner, regex
import sys


# Extracció del cos del missatge en format html si està disponible. Si no, s'extreu en format text pla.
def GetMessageBodyHtml(raw_msg):
	try:
		msg_str = base64.urlsafe_b64decode(raw_msg['raw'].encode('ASCII'))
		mime_msg = email.message_from_string(msg_str)
		messageMainType = mime_msg.get_content_maintype()
		if messageMainType == 'multipart':
			return str(mime_msg.get_payload(0))	
		elif messageMainType == 'text':
			return mime_msg.get_payload()

	except errors.HttpError, error:
		print('An error ocurred: %s' % error)


# Extracció de links del cos del missatge utilitzant regex
def parse_urls(body):
	result = re.findall(regex.web_regex, body)
	i = 0
	urls = []	
	for url in result:
		urls.append(result[i][0])
		i = i + 1
	urls = list(set(urls)) # Elimina duplicats
	return urls


# Comprovar al correu si hi ha correus no llegits i analitzar-los
def checkmail():
	# Setup l'API de Gmail
	SCOPES = 'https://www.googleapis.com/auth/gmail.modify'
	store = file.Storage('credentials.json')
	creds = store.get()
	if not creds or creds.invalid:
		flow = client.flow_from_clientsecrets('client_secret.json', SCOPES)
		creds = tools.run_flow(flow, store) 
	try:	
		service = build('gmail', 'v1', http=creds.authorize(Http()))
	except httplib2.ServerNotFoundError:
		print(colors.CYAN + "\nNo s'ha trobat el servidor de Gmail. Comprova connexió a Internet.\n" + colors.NORMAL)
		return

	# Agafar els identificadors dels missatges no llegits
	try:
		response = service.users().messages().list(userId='me',maxResults=100,q='is:unread AND is:inbox').execute()
		unread_msgs = []
		if 'messages' in response:
			unread_msgs.extend(response['messages'])
	except errors.HttpError, error:
		print('An error ocurred: %s' % error)


	# Descarregar-se la informació que volem de cada missatge no llegit
	for msg in unread_msgs:
		m_id = msg['id']
		print(colors.LOGS + "\nAnalitzar correu: " + m_id + "\n***************************************************" + colors.NORMAL)

		# Extracció del cos del missatge
		raw_msg = service.users().messages().get(userId='me', id=m_id, format='raw').execute()

		# Conversió del cos del missatge en HTML o text pla
		msg_body = GetMessageBodyHtml(raw_msg)
	
		# Extracció de links del cos del missatge
		urls = parse_urls(msg_body)
		if mirar_redirects:
			urls = redirects.get_redirects(urls)
		print(colors.BANNER + "URLs extretes a analitzar: \n" + "\n".join(str(x) for x in urls) + colors.NORMAL)
		if urls == []:
			service.users().messages().modify(userId='me', id=m_id, body={'removeLabelIds': ['UNREAD']}).execute()
			print(colors.CYAN + "\nNo s'han trobat enllaços a analitzar\n" + colors.NORMAL)
	
		# Anàlisi de les URLs i actuació de GLUTTON
		marcar_llegit = True
		for url in urls:
			print("")
			phish_vt = virustotal.analisi_virustotal(url)
			phish_bc = bluecoat.analisi_bluecoat(url)
			phish_sb = safebrowsing.analisi_google(url)
			if phish_vt or phish_bc or phish_sb:		
				# Moure el correu a PHISHING			
				service.users().messages().modify(userId='me', id=m_id, body={'addLabelIds': ['Label_1'], 'removeLabelIds': ['INBOX']}).execute()
				marcar_llegit = False
				if complet == False: break

		if marcar_llegit:
			# Marcar el correu com a LLEGIT
			service.users().messages().modify(userId='me', id=m_id, body={'removeLabelIds': ['UNREAD']}).execute()
		print("")
	
		print(colors.LOGS + "Analisi del correu finalitzat\n\n" + colors.NORMAL)


"""
EXECUCIÓ DEL PROGRAMA

"""

# Decidir si mirar per redirects i si analitzar totes les URLs o només fins una que sigui maliciosa
try:
	param1 = sys.argv[1]
	param2 = sys.argv[2]
except:
	param1 = ""
	param2 = ""

mirar_redirects = param1 != "no-redirects"
complet = param2 == "complet"

banner.inici()
while True:
	checkmail()
	time.sleep(10)


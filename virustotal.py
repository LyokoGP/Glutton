# -*- coding: latin-1 -*-
# Virus total analysis

import requests
import json
import time
import colors


# Comprovar URL a base de dades de VirusTotal a partir de url
def url_report(apikey, resource):
	vt_report = 'https://www.virustotal.com/vtapi/v2/url/report'
	params = {'apikey': apikey, 'resource': resource}
	response = requests.get(vt_report, params=params)
	status_code = response.status_code	
	while status_code == 204:
		time.sleep(2)
		response = requests.get(vt_report, params=params)
		status_code = response.status_code
	response_json = response.json()	
	return response_json


# Analitzar URL no registrada a VirusTotal
def url_scan(apikey, url_analitzada):
	vt_scan = 'https://www.virustotal.com/vtapi/v2/url/scan'
	params = {'apikey': apikey, 'url': url_analitzada}
	response = requests.post(vt_scan, data=params)
	status_code = response.status_code
	while status_code == 204:
		time.sleep(2)
		response = requests.post(vt_scan, data=params)
		status_code = response.status_code	
	response_json = response.json()
	return response_json


# Construcció array a retornar
def build_array(response_json):
	try: 
		positives = str(response_json["positives"])
		total = str(response_json["total"])
	except KeyError:
		positives = "-1"
		total = "-1"
	return [positives, total]


# Analisi de la URL
def analisi(url_analitzada): # Retorna una array amb: [positius, totals]
	apikey = 'INTRODUIR_API_KEY'
	print("Procedint a l'analisi de la URL: " + colors.NEGRETA + url_analitzada + colors.NORMAL)

	# Busca a veure si es troba a la base de dades de VT
	response_json = url_report(apikey, url_analitzada)

	# Control de resposta buida	
	if response_json == []:
		print(colors.CYAN + "Resposta json buida (Error 001)" + colors.NORMAL)
		return ["-1","-1"]

	response_code = str(response_json["response_code"])

	if response_code == "1": # En cas que estigui llistada
		print("La URL a analitzar es troba a la base de dades de VirusTotal")
		return build_array(response_json)

	elif response_code == "0": # En cas que no estigui analitzada
		print("Analitzant URL a VirusTotal...")
		response_scan = url_scan(apikey, url_analitzada)
		if str(response_scan["response_code"]) != "1":
			return ["-3","-3"]
		time.sleep(5)
		response_json_report = url_report(apikey, url_analitzada)
		code = str(response_json_report["response_code"])
		iteration = 0
		while code != "1" and iteration < 3:
			time.sleep(5)
			response_json_report = url_report(apikey, url_analitzada)
			code = str(response_json_report["response_code"])
			iteration = iteration + 1
		return build_array(response_json_report)
	
	elif response_code == "-2": # En cas que s'estigui analitzant
		print("Analisi en cua, esperant resultats...")
		code = response_code
		while code != "1":
			response_json_report = url_report(apikey, url_analitzada)
			code = str(response_json_report["response_code"])
		return build_array(response_json_report)

	else:
		print(colors.CYAN + "[ERROR_GREU] El response_code es: " + response_code + colors.NORMAL)
		return ["-2","-2"]


def analisi_virustotal(url): # Retorna si es possible phishing o no (TRUE o FALSE)
	result = analisi(url)
	positius = result[0]
	total = result[1]

	if total == '-2':
		print(colors.CYAN + "VirusTotal: Hi ha hagut un error GREU. Aixo no hauria de passar mai" + colors.NORMAL)
		return False
	if total == '-1' or total == '0':
		print(colors.CYAN + "VirusTotal: Resposta buida" + colors.NORMAL)
		return False
	if total == '-3':
		print(colors.CYAN + "VirusTotal: Format de la URL incorrecte" + colors.NORMAL)
		return False
	
	result = "(" + positius + "/" + total + ")"
	if positius == '0':
 		print(colors.VERD + "VirusTotal: La URL no s'ha detectat com a maliciosa " + result + colors.NORMAL)
		return False
	if positius == '1' or positius == '2':
		print(colors.GROC + "VirusTotal: Possibilitat que sigui phishing " + result + colors.NORMAL)
		return True
	else:
		print(colors.VERMELL + "VirusTotal: Alta probabilitat de ser phishing " + result + colors.NORMAL)
		return True

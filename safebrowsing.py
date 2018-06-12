# -*- coding: latin-1 -*-
# Google Safe Browsing URL checker

import requests, json
import colors

def analisi_google(url):
	api_key = 'INTRODUIR_API_KEY'
	get_url = 'https://sb-ssl.google.com/safebrowsing/api/lookup?client=tfg&key=' + api_key + '&appver=1.5.2&pver=3.1&url=' + url
	response = requests.get(get_url)
	code = str(response.status_code)
	if code == "200":
		print(colors.VERMELL + "Google Safe Browsing categoritza com a: " + response.content + colors.NORMAL)
		return True
	elif code == "204":
		print(colors.VERD + "La URL no es troba a Google Safe Browsing " + colors.NORMAL)
		return False
	else:
		print(colors.CYAN + "Google Safe Browsing: Error " + code + " : URL mal formada" + colors.NORMAL)
		return False


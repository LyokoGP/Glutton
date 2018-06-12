import json
import requests
import colors


class BlueCoat(object):
    def __init__(self):
        self.url_base = "https://sitereview.bluecoat.com/resource/lookup"
        self.headers = {"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"}

    def bluecoat(self, url):
        payload = {"url": url, "captcha":""}
        
        try:
            self.req = requests.post(
                self.url_base,
                headers=self.headers,
                data=json.dumps(payload),
            )
        except requests.ConnectionError:
            return False

        return json.loads(self.req.content.decode("UTF-8"))

    def check_response(self, response):
        if self.req.status_code != 200:
            return False
        else:
            self.category = response["categorization"][0]["name"]
            self.date = response["translatedRateDates"][0]["text"][0:35]
            self.url = response["url"]
            return True



def analisi_bluecoat(url):
    bc = BlueCoat()
    response = bc.bluecoat(url)
    if response == False:
        print(colors.CYAN + "BlueCoat: connection error" + colors.NORMAL)
        return False
    result = bc.check_response(response)
    if result:
        llista = ["Malicious Outbound Data/Botnets", "Malicious Sources/Malnets", "Phishing", "Scam/Questionable/Illegal", "Suspicious"]
        if bc.category in llista:
            print(colors.VERMELL + "Categoria BlueCoat: " + s.category + colors.NORMAL)
            return True
        elif bc.category == "Uncategorized":
            print(colors.GROC + "URL no categoritzada per BlueCoat" + colors.NORMAL)
            return False
        else:
            print(colors.VERD + "Categoria BlueCoat: " + s.category + colors.NORMAL)
            return False
    else:
        print(colors.CYAN + "BlueCoat no ha pogut analitzar aquesta URL" + colors.NORMAL)
        return False


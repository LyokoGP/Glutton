import requests, urllib3

def comprovar_redireccions(url):
    try:
        r = requests.get(url, allow_redirects=False, timeout=0.5)
        if 300 <= r.status_code < 400:
            return r.headers['location']
        else:
            return '[no redirect]'
    except requests.exceptions.Timeout:
        return '[timeout]'
    except requests.exceptions.InvalidURL:
        return '[invalid url]'
    except requests.exceptions.ConnectionError:
        return '[connection error]'


def llistar_redireccions(url):
    url_to_check = url if url.startswith('http') else "http://%s" % url
    try:
        redirect_url = comprovar_redireccions(url_to_check)
    except urllib3.exceptions.LocationParseError:
        redirect_url = '[invalid url]'
    redirects = [url]
    i = 0
    while i < 20:	
        if redirect_url == '[no redirect]' or redirect_url == '[timeout]' or redirect_url == '[connection error]' or redirect_url == '[invalid url]':
            return redirects
        else:
            url_to_check = redirect_url if redirect_url.startswith('http') else "http://%s" % redirect_url
            redirects.append(url_to_check)
            redirect_url = comprovar_redireccions(url_to_check)
            i = i + 1
    return ['TOO MANY REDIRECTS']


def get_redirects(urls):
    url_list = []	
    for url in urls:
        result = llistar_redireccions(url)
        url_list.extend(result)
    return url_list	


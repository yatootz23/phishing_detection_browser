from urllib.parse import urlparse,urlencode
from ipaddress import ip_network, ip_address
import tldextract
import re
import time
import pandas as pd
import whois
from datetime import datetime
import socket
import urllib
import urllib.parse
import urllib.request as ur
from googlesearch import search
from bs4 import BeautifulSoup


def Tokenise(url):
    if url=='':
        return [0,0,0]
    token_word=re.split('\W+',url)
    no_ele=sum_len=largest=0
    for ele in token_word:
        l=len(ele)
        sum_len+=l
        if l>0:                                        ## for empty element exclusion in average length
            no_ele+=1
        if largest<l:
            argest=l
    try:
        return [float(sum_len)/no_ele,no_ele,largest]
    except:
        return [0,no_ele,largest]


def getDomain(url):
    domain = urlparse(url).netloc
    if re.match(r"^www.",domain):
        domain = domain.replace("www.","")
    return domain


def lengthURL(url):
    if len(url) < 74:
        length = 0      #label for legitimate
    else:
        length = 1     #label for phishing      
    return length


def shortURL(url):
    match=re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me\.gd|tr\.im|link\.zip\.net',url)
                    
    if match:
        return 1       #label for phishing
    else:
        return 0       #label for legitimate  


def atURL (url):
    if "@" in url:
        at = 1        #label for phishing
    else:
        at = 0       #label for legitimate
    return at


def specialcharCount(url):
    cnt = 0
    special_characters = [';','+=','_','?','=','&','[',']','/',':']
    for each_letter in url:
        if each_letter in special_characters:
            cnt = cnt + 1
    return cnt


def securityWords(token_word):
    sec_word = ['token', 'security', 'PayPal', 'login', 'bank', 'update','confirm', 'account', 'banking','secure', 
    'ebayisapi', 'webscr', 'signin', 'mail', 'install','toolbar','johnsondistribuidores', 'Account', 
    '420641','compte','AVS','redirection','Logon','jscritp','ss','11930758','gouv', '201609','xyleo','disturb', 
    'webstat', 'DESATUALIZADOATUALIZA','WUCOMWEB','guiadelacerveza','rl', '09u8h76f','fkhfgfg','docments', 
    'garyferone','47236','novy','facturation','sn','suspende','nabbanque','dTaZAyRgypW659snnM3Rnmck','Xclusiv', 
    'joesantibanez','wuwu','notificationtips2016310', 'svijet','lp4','layout','9377wan','joomla','fabdmr' 
    'e175e0395a5fcceb980485ac37f043f1','425169','savepop','wellsfargo0o','autovendido','mirror3','mjes','surgicals', 
    'horas','usbootv1','phmtllqsewlgejrea3r','conexaoengenharia','fapparaguay']

    cnt=0
    for ele in sec_word:
        if(ele in token_word):
            cnt+=1

    return cnt


def digitCount(url):

    return sum(c.isdigit() for c in url)


def httpDomain(url):
    http_count = url.count('http')
    https_count = url.count('https')
    http_cnt = http_count - https_count #correcting the miscount of https as http

    if http_cnt < 2:
        return 0
    else:
        return 1


def dotCount(url):
    if url.count(".") < 4:
        return 0             # legitimate
    else:
        return 1            # phishing


def hyphenCount(url):
    if url.count("-") < 2:
        return 0            # legitimate
    else:
        return 1           # phishing


def hasIP(url):
    try:
        ipaddress.ip_address(url)
        ip = 1
    except:
        ip = 0
    return ip


def prefixSuffix(url):
    if "-" in urlparse(url).netloc:
        return 1            # phishing
    else:
        return 0            # legitimate


def subdomCount(url):

    # separate protocol and domain then count the nu ber of dots in domain
    
    domain = url.split("//")[-1].split("/")[0].split("www.")[-1]
    if(domain.count('.')<=1):
        return 0
    else:
        return 1


def redirect(url):
    pos = url.rfind('//')
    if pos > 6:
        if pos > 7:
            return 1
        else:
            return 0
    else:
        return 0


def hasExe(url):
    if ".exe" in url:
        return 1  # '.exe' present in url
    else:
        return 0  # '.exe' not present in url


def domAge (url):
    try:
        w = whois.whois(url)
        start_date = w.creation_date
        current_date = datetime.datetime.now()
        age = 0
        try:
            age = (current_date - start_date[0]).days
        except:
            age = (current_date - start_date).days
        if(age >= 180):
            return 0
        else:
            return 1
    except Exception as e:
        return 1


def domReg_life(url):
    try:
        w = whois.whois(url)
        update_date = w.updated_date
        expiration_date = w.expiration_date
        expires_on = 0
        try:
            expires_on = (expiration_date[0] - update_date[0]).days
        except:
            try:
                expires_on = (expiration_date - update_date).days
            except:
                try:
                    expires_on = (expiration_date[0] - update_date).days
                except:
                    expires_on = (expiration_date - update_date[0]).days

        if(expires_on <= 365):
            return 1
        else:
            return 0
    except:
        return 1


def dnsRecord(whois_result):
    dns = 0
    try:
        domain_name = whois.whois(urlparse(url).netloc)
    except:
        dns = 1
    
    if dns == 1:
        return 1
    else:
        return 0


opener = ur.build_opener()
opener.addheaders = [('User-agent', 'Mozilla/5.0')]


def webTraffic(url):
    xmlpath='http://data.alexa.com/data?cli=10&dat=snbamz&url='+url

    try:
        xml= urllib2.urlopen(xmlpath)
        dom = minidom.parse(xml)
        rank_host=find_ele_with_attribute(dom,'REACH','RANK')

        rank = int(rank_host)
    except:
        return 1
    if rank <100000:
        return 0
    else:
        return 1


def generate_ranking(url):
    rank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {"name": domain})

    # Extracts global rank of the website
    try:
        global_rank = int(re.findall(r"Global Rank: ([0-9]+)", rank_checker_response.text)[0])
    except:
        global_rank = -1


def pageRank(url):
    try:
        if siterank > 0 and siterank < 100000:
            return 1
        else:
            return 0
    except:
        return 0


def googleIndex(url):
    
    site = search(url, 5)
    return 0 if site else 1


def featureExtraction(url):
    
    features = []

    #Lexical features (14)
    #features.append(getDomain(url))
    features.append(lengthURL(url))
    features.append(shortURL(url))
    features.append(atURL(url))
    features.append(specialcharCount(url))
    features.append(securityWords(url))
    features.append(digitCount(url))
    features.append(httpDomain(url))
    features.append(dotCount(url))
    features.append(hyphenCount(url))
    features.append(hasIP(url))
    features.append(prefixSuffix(url))
    features.append(subdomCount(url))
    features.append(redirect(url))
    features.append(hasExe(url))

    # WHOIS Features (3)
    features.append(domAge(url))
    features.append(domReg_life(url))
    features.append(dnsRecord(url))

    # POPULARITY Features (3)
    features.append(webTraffic(url))
    features.append(pageRank(url))
    features.append(googleIndex(url))
    
    return features

#print(featureExtraction('https://play.alienworlds.io'))
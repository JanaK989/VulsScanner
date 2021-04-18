import os
from os import path
import tweepy
import csv
import datetime
import requests
from bs4 import BeautifulSoup
import pandas as pd

# with open('twitter_keys.txt') as tk:
consumer_key = 'XAD9sZmdVdef7cH3SkHJSbsUQ'
consumer_secret = 'rrFzLHuaIkTiKRLTFKaKewMGm8pdB0DfnIDRMvdsIWZ0ZJ18m5'
access_token = '1371891471016726532-4cmI4HF8DWIanvlAnpc5xknxwYHMes'
access_token_secret = 'iDBTI1QeHqOuasC16l5TN1lrZdfFlQ71WvplPblJUpzGl'
# Twitter API autorizacia
auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
auth.set_access_token(access_token, access_token_secret)
api = tweepy.API(auth)

# ###########################################################################

name = 'db.csv'
nvd_url = "https://nvd.nist.gov/vuln/detail/"
act_date = datetime.datetime.now()
cvss_column = []
critical_vuls = []
sys_file = open('systems.txt', 'r')
lines = [line.rstrip('\n') for line in sys_file]
word_set = set(lines)

# ##############################################

def get_cvss(url):
    try:
        r = requests.get(url)
        soup = BeautifulSoup(r.text, 'html.parser')
        cvss = soup.find('span', attrs={'class': 'severityDetail'}).find('a').text
        return cvss
    except(AttributeError, Exception) as e:
        return "N/A"


def create_email(list_vuls):
    email_date = datetime.datetime.now().strftime("%Y_%m_%d")
    file_name = email_date + ".txt"
    f = open(file_name, "w+")
    f.write('Zoznam kritických zraniteľností:\n\n')
    for i in list_vuls:
        (date, cve, description, asset, cvss, url) = i
        f.write(f'Dátum: {date}\n')
        f.write(f'ID: {cve}\n')
        f.write(f'CVSS: {cvss}\n')
        desc = description.split()[1:-1]
        desc_str = ' '.join([str(word) for word in desc])
        f.write(f'Popis: {desc_str}\n')
        f.write(f'Systémy: {asset}\n')
        f.write(f'Viac informácií: {url}\n\n')
        f.write('# # #\n\n')
    print(f'Súbor s názvom {file_name} bol vytvorený a je prirpavený na odoslanie lokálnym správcom.')

# ################################################

# update cvss in the database, if they are still N/A
if path.exists(name):
    print('Aktualizujem  databázu...')
    with open(name, 'r') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        line_count = 0
        for row in csv_reader:
            if len(row) == 0:
                continue
            if line_count == 0:
                line_count += 1
            else:
                if row[5] == 'N/A':
                    cve = row[1]
                    new_url = nvd_url + cve
                    cvss = get_cvss(new_url)
                    cvss_column.append(cvss)
                    if cvss != 'N/A' and float(cvss.split()[0]) >= 9.0 and row[4] != 'none':
                        vul_info = (row[0], row[1], row[3], row[4], cvss, new_url)
                        critical_vuls.append(vul_info)

                    line_count += 1
                else:
                    cvss_column.append(row[5])
                    line_count += 1

    df = pd.read_csv(name)
    df["CVSS"] = cvss_column
    df.to_csv(name, index=False)
    print('Databáza bola úspešne aktualizovaná!')
# ##############################################

# get new tweets
csvFile = open(name, 'a')
csvWriter = csv.writer(csvFile)
filesize = os.path.getsize(name)
if filesize == 0:
    csvWriter.writerow(["Date", "CVE", "Year", "Description", "Asset", "CVSS"])
new_amount = 0
print('Získavam nové zraniteľnosti z Twitteru...')
tweets = api.user_timeline(screen_name="CVEnew", count=200, include_rts=False,

                           tweet_mode='extended')
for info in tweets:
    if info.created_at > (act_date - datetime.timedelta(1)):
        new_amount += 1
        tweet = info.full_text
        cve = tweet.split()[0]
        year = cve[4:8]
        text = tweet[len(cve):]
        new_url = nvd_url + cve
        cvss = get_cvss(new_url)
        phrase_set = set(text.lower().split())
        asset = word_set.intersection(phrase_set)
        if len(asset) == 0:
            asset = "none"
        if cvss != 'N/A' and float(cvss.split()[0]) >= 9.0 and asset != 'none':
            vul_info = (info.created_at.strftime("%d.%m.%y"), cve, text, asset, cvss, new_url)
            critical_vuls.append(vul_info)
        csvWriter.writerow([info.created_at.strftime("%d.%m.%y"), cve, year, text.encode('utf-8'), asset, cvss])

print(f'Databáza bola doplnená o {new_amount} nových zraniteľností!')

if critical_vuls:
    create_email(critical_vuls)

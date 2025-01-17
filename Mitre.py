import requests
import json

url = "https://www.virustotal.com/api/v3/files/999eb1840c209aa70a84c5cf64909e5f/behaviour_mitre_trees"

headers = {
    "accept": "application/json",
    "x-apikey": "9aa1e017d10d318069b654469cd2826d4111eff92d2479f660a60318d8f2b10c"
}

response = requests.get(url, headers=headers)
data = json.loads(response.text)

x = 0

try:

    while x < len(data['data']['Zenbox']['tactics']):

        print('Tactic: ', data['data']['Zenbox']['tactics'][x]['name'])
        y = 0

        while y < len(data['data']['Zenbox']['tactics'][x]['techniques']):

            print(data['data']['Zenbox']['tactics'][x]['techniques'][y]['name'])
            y = y + 1

        x = x + 1

except KeyError:

    print('No report')
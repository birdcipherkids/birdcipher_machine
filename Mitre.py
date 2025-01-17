import requests
import json

url = "https://www.virustotal.com/api/v3/files/8f80cf878a3e05c06c9d03646443e41d/behaviour_mitre_trees"

headers = {
    "accept": "application/json",
    "x-apikey": "9aa1e017d10d318069b654469cd2826d4111eff92d2479f660a60318d8f2b10c"
}

response = requests.get(url, headers=headers)
data = json.loads(response.text)

x = 0

try:

    while x < len(data['data']['CAPE Sandbox']['tactics']):

        print('Tactic: ', data['data']['CAPE Sandbox']['tactics'][x]['name'])
        y = 0

        while y < len(data['data']['CAPE Sandbox']['tactics'][x]['techniques']):

            print(data['data']['CAPE Sandbox']['tactics'][x]['techniques'][y]['name'])
            y = y + 1

        x = x + 1

except KeyError:

    print('No report')
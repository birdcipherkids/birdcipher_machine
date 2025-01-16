import requests
import json

url = "https://www.virustotal.com/api/v3/files/d1bdc5aaa294b4c52678c4c60f052569/behaviour_mitre_trees"

headers = {
    "accept": "application/json",
    "x-apikey": "9aa1e017d10d318069b654469cd2826d4111eff92d2479f660a60318d8f2b10c"
}

response = requests.get(url, headers=headers)
data = json.loads(response.text)

x = 0

try:

    while x < len(data['data']['Zenbox']['tactics']):

        print(data['data']['Zenbox']['tactics'][x]['name'])
        x = x + 1

except KeyError:

    print('No report')
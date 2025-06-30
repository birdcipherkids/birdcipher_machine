import requests
import json

url = "https://www.virustotal.com/api/v3/urls/fbed8d711f240852f54164f7c196f19277d022fc8bd02e7751b9246cdfe9b62d"

headers = {
    "accept": "application/json",
    "x-apikey": "9aa1e017d10d318069b654469cd2826d4111eff92d2479f660a60318d8f2b10c"
}

response = requests.get(url, headers=headers)

data = json.loads(response.text)

print(data['data']['attributes']['categories']['Forcepoint ThreatSeeker'])

#print(response.text)
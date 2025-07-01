import requests
import json

url = "https://www.virustotal.com/api/v3/urls/b99117b3ec674ad0a2c198089d3c156bf65819ff6c32f354476f1bfefcae58d3"

headers = {
    "accept": "application/json",
    "x-apikey": "9aa1e017d10d318069b654469cd2826d4111eff92d2479f660a60318d8f2b10c"
}

response = requests.get(url, headers=headers)

#data = json.loads(response.text)

print(response.text)

#print(response.text)
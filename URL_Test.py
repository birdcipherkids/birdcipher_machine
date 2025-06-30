import requests

url = "https://www.virustotal.com/api/v3/urls/bddf5bac24d8072eb38da194e557e263776820c31a3f001e5660926593f8594c"

headers = {
    "accept": "application/json",
    "x-apikey": "9aa1e017d10d318069b654469cd2826d4111eff92d2479f660a60318d8f2b10c"
}

response = requests.get(url, headers=headers)

print(response.text)
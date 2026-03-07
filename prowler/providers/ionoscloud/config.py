"""IONOS Cloud Provider Configuration Constants"""

IONOSCLOUD_API_HOST = "https://api.ionos.com/cloudapi/v6"

# SDK timeout settings (seconds)
IONOSCLOUD_SDK_READ_TIMEOUT = 60
IONOSCLOUD_SDK_CONNECT_TIMEOUT = 10

# IONOS Cloud Locations
IONOSCLOUD_LOCATIONS = {
    "de/fra": "Germany (Frankfurt)",
    "de/txl": "Germany (Berlin)",
    "gb/lhr": "United Kingdom (London)",
    "gb/bhx": "United Kingdom (Birmingham)",
    "es/vit": "Spain (Vitoria-Gasteiz)",
    "us/las": "United States (Las Vegas)",
    "us/ewr": "United States (Newark)",
    "fr/par": "France (Paris)",
}

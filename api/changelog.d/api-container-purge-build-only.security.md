Removed `gnupg` and `apt-transport-https` from the API container image; `wget` is retained because the Compose healthcheck invokes it

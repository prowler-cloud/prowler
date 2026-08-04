Removed `wget`, `gnupg` and `apt-transport-https` from the SDK runtime image; the API image keeps `wget` because its Compose healthcheck invokes it

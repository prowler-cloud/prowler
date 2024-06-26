import toml

data = toml.load("pyproject.toml")
# Modify field
data["tool"]["poetry"]["name"] = "prowler-cloud"

# To use the dump function, you need to open the file in 'write' mode
f = open("pyproject.toml", "w")
toml.dump(data, f)
f.close()

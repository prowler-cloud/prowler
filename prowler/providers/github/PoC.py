from os import getenv

from github import Auth, Github

TOKEN = getenv("GITHUB_PERSONAL_ACCESS_TOKEN")

auth = Auth.Token(TOKEN)
g = Github(auth=auth)

for repo in g.get_user().get_repos():
    print(repo)

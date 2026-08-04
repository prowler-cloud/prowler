Compliance report output directory failures are now logged with the exception attached and fingerprinted by `errno` in Sentry, so `ENOSPC`, `ENOENT` and `EACCES` no longer share a single issue

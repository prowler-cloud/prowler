GCP Cloud Functions gen2 IAM policy retrieval now uses a per-request HTTP client, preventing a process crash from concurrent thread-unsafe `httplib2` access when a project has several gen2 functions

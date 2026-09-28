`DELETE /api/v1/tasks/{id}` requires the permission of the operation that queued the task and rejects provider deletions, and `GET /api/v1/tasks` only returns tasks of providers visible to the role

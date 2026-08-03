Memory leak in HTTP mode caused by streamable-HTTP sessions being retained for the process lifetime when clients never sent `DELETE /mcp`; the server now runs stateless

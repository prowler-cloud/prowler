Fixed promptfoo report path of the LLM provider from a predictable /tmp file to a private temporary file created with tempfile.mkstemp, closing a symlink/race condition on shared hosts

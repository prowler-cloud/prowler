Output writers no longer leave the file open and incomplete when the last streamed batch has no rows, which truncated CSV outputs and left OCSF and HTML outputs unterminated

"""Argument types shared by every tool in this server."""

from typing import Annotated

from pydantic import StringConstraints

# The identifiers tools take -- a scan UUID, a query id, a Jira project key --
# are required because there is nothing sensible to do without them. A model
# that does not have one to hand tends to send an empty string rather than omit
# the argument, and an empty string is not caught by "required": it travels into
# a URL path or a request body and comes back as a 404 or an opaque API error
# ("This field may not be blank") that says nothing about which argument was at
# fault. Rejecting it here names the argument instead, and `minLength` puts the
# constraint in the tool schema so a client can see it before calling.
#
# Whitespace is stripped first, so " abc " is accepted as "abc" and "   " is
# rejected like "".
NonBlankStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]

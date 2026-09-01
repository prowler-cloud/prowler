from freezegun import configure

# Skip lazy Okta imports building Pydantic schemas against frozen datetime.
configure(extend_ignore_list=["okta"])

from boto3 import session


################## AWS PROVIDER
class AWS_Provider:
    def __init__(self, profile):
        self.aws_session = session.Session(profile_name=profile)

    def get_session(self):
        return self.aws_session


def provider_set_profile(profile):
    global session
    session = AWS_Provider(profile).get_session()


# ################## AWS Service
# class AWS_Service():
#     def __init__(self, service, session):
#         self.client = session.client(service)

#     def get_client(self):
#         return self.client

from prowler.providers.common.provider import Provider
from prowler.providers.googleworkspace.services.chat.chat_service import Chat

chat_client = Chat(Provider.get_global_provider())

from pydantic import BaseModel
from prowler.providers.opennebula.lib.service.service import OpennebulaService
from prowler.lib.logger import logger
import hashlib
import os

class ACCService(OpennebulaService):
    def __init__(self, provider):
        super().__init__(provider)
        self.users : list[User] = []
        self.__get_users__()
        self.__check_weak_passwords__()
        self.__get_user_tokens__()

    def _load_common_password_hashes_(self, file):
        basedir = os.path.dirname(os.path.abspath(__file__))
        filepath = os.path.join(basedir, file)
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
            return {hashlib.sha256(line.strip().encode()).hexdigest() for line in file}

    def _is_weak_password_(self, user_hash, common_hashes):
        return user_hash in common_hashes

    def __check_weak_passwords__(self):
        """
        Check if users have weak passwords by comparing against common password hashes.
        Updates the weak_password field for each user.
        """
        common_hashes = self._load_common_password_hashes_('10-million-password-list-top-1000000.txt')
        for user in self.users:
            user.weak_password = self._is_weak_password_(user.password, common_hashes)

    def __get_users__(self):
        """
        Get users from OpenNebula
        """
        try:
            userpool = self.client.userpool.info()
            for user in userpool.USER:
                self.users.append(User(
                    id=user.ID,
                    gid=user.GROUPS.ID,
                    name=user.NAME,
                    password=user.PASSWORD,
                    group=user.GNAME,
                    auth_driver=user.AUTH_DRIVER,
                    enabled=user.ENABLED,
                    weak_password=False,
                    tokens=[]
                ))
        except Exception as error:
            logger.error(f"Error al obtener usuarios: {error}")

    def __get_user_tokens__(self):
        """
        Retrieve login tokens for each user
        """
        for user in self.users:
            try:
                user_info = self.client.user.info(int(user.id))
                tokens = []
                if hasattr(user_info, "LOGIN_TOKEN"):
                    login_tokens = user_info.LOGIN_TOKEN
                    if isinstance(login_tokens, list):
                        for token in login_tokens:
                            tokens.append({
                                "value": token.TOKEN,
                                "expiration": int(token.EXPIRATION_TIME)
                            })
                    else:
                        tokens.append({
                            "value": login_tokens.TOKEN,
                            "expiration": login_tokens.EXPIRATION_TIME
                        })
                user.tokens = tokens
            except Exception as error:
                logger.error(f"Error obteniendo tokens del usuario {user.name}: {error}")

class User(BaseModel):
    id: str
    gid: list
    name: str
    password: str
    group: str
    auth_driver: str
    enabled: bool
    weak_password: bool
    tokens: list[dict]
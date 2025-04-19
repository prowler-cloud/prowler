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

    def _load_common_password_hashes_(self, file):
        basedir = os.path.dirname(os.path.abspath(__file__))
        filepath = os.path.join(basedir, file)
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
            return {hashlib.sha256(line.strip().encode()).hexdigest() for line in file}

    def _is_weak_password_(self, user_hash, common_hashes):
        return user_hash in common_hashes

    def __get_users__(self):
        """
        Get users from OpenNebula
        """
        common_hashes = self._load_common_password_hashes_('10-million-password-list-top-1000000.txt')
        try:
            userpool = self.client.userpool.info()
            for user in userpool.USER:
                self.users.append(User(
                    id=user.ID,
                    name=user.NAME,
                    password=user.PASSWORD,
                    group=user.GNAME,
                    auth_driver=user.AUTH_DRIVER,
                    enabled=user.ENABLED,
                    weak_password=self._is_weak_password_(user.PASSWORD, common_hashes)
                ))
        except Exception as error:
            logger.error(f"Error al obtener usuarios: {error}")

class User(BaseModel):
    id: str
    name: str
    password: str
    group: str
    auth_driver: str
    enabled: bool
    weak_password: bool        
        
import json
import os

from prowler.lib.mutelist.mutelist import Mutelist


class IonosMutelist(Mutelist):
    """
    Clase Mutelist para IONOS Cloud.
    
    Esta clase se encarga de cargar, verificar y actualizar una lista de elementos (por ejemplo,
    identificadores de checks) que se desean ignorar durante la auditoría.
    
    El archivo de configuración se espera que tenga el siguiente formato JSON:
    
    {
        "muted_checks": [
            "CHECK_ID_1",
            "CHECK_ID_2"
        ]
    }
    """

    def __init__(
        self, 
        mutelist_content: dict = {},
        mutelist_path: str = None, 
        session: any = None,
    ) -> "IonosMutelist":
        """
        Inicializa la instancia de Mutelist cargando la configuración desde el archivo indicado.
        Si el archivo no existe o no es válido, se inicia con una lista vacía.
        """
        self._mutelist_path = mutelist_path
        self._mutelist = self.load_mutelist()

    def load_mutelist(self) -> dict:
        """
        Carga la configuración del mutelist desde un archivo JSON.
        
        :return: Diccionario con la configuración (por ejemplo, la clave "muted_checks").
        """
        # Verifica que self.mutelist_path sea válido
        if not self._mutelist_path or not os.path.isfile(self._mutelist_path):
            # Si la ruta no se proporcionó o el archivo no existe, retorna un diccionario vacío.
            return {}
        try:
            # Se asume que 'get_mutelist_file_from_local_file' lee y devuelve el contenido del archivo.
            return self.get_mutelist_file_from_local_file(self._mutelist_path)
        except Exception as e:
            print(f"Error al cargar el mutelist desde {self.mutelist_path}: {e}")
            return {}

    def is_muted(self, check_id: str) -> bool:
        """
        Verifica si un identificador de check está marcado para ser ignorado.
        
        :param check_id: Identificador del check a verificar.
        :return: True si el check está muteado; False en caso contrario.
        """
        muted_checks = self.mutelist.get("muted_checks", [])
        return check_id in muted_checks

    def add_muted_check(self, check_id: str):
        """
        Agrega un identificador de check a la lista de elementos muteados y actualiza el archivo.
        
        :param check_id: Identificador del check a agregar.
        """
        if "muted_checks" not in self.mutelist:
            self.mutelist["muted_checks"] = []
        if check_id not in self.mutelist["muted_checks"]:
            self.mutelist["muted_checks"].append(check_id)
            self.save_mutelist()

    def remove_muted_check(self, check_id: str):
        """
        Remueve un identificador de check de la lista de elementos muteados y actualiza el archivo.
        
        :param check_id: Identificador del check a remover.
        """
        if "muted_checks" in self.mutelist and check_id in self.mutelist["muted_checks"]:
            self.mutelist["muted_checks"].remove(check_id)
            self.save_mutelist()

    def save_mutelist(self):
        """
        Guarda la configuración actual del mutelist en el archivo JSON.
        """
        try:
            with open(self.filepath, 'w') as file:
                json.dump(self.mutelist, file, indent=4)
        except Exception as e:
            print(f"Error al guardar el mutelist en {self.filepath}: {e}")

    def is_finding_muted(self, finding: dict) -> bool:
        """
        Verifica si un hallazgo (finding) debe ser muteado.
        
        Se espera que 'finding' sea un diccionario que contenga un identificador de check,
        por ejemplo, en la clave 'check_id'.
        """
        check_id = finding.get("check_id")
        return self.is_muted(check_id)


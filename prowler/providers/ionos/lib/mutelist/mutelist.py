import json
import os

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

    def __init__(self, filepath: str):
        """
        Inicializa la instancia de Mutelist cargando la configuración desde el archivo indicado.
        Si el archivo no existe o no es válido, se inicia con una lista vacía.
        
        :param filepath: Ruta al archivo JSON que contiene la configuración del mutelist.
        """
        self.filepath = filepath
        self.mutelist = self.load_mutelist()

    def load_mutelist(self) -> dict:
        """
        Carga la configuración del mutelist desde un archivo JSON.
        
        :return: Diccionario con la configuración (por ejemplo, la clave "muted_checks").
        """
        if not os.path.isfile(self.filepath):
            # Si el archivo no existe, retorna un diccionario vacío
            return {}
        try:
            with open(self.filepath, 'r') as file:
                data = json.load(file)
            return data
        except Exception as e:
            print(f"Error al cargar el mutelist desde {self.filepath}: {e}")
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

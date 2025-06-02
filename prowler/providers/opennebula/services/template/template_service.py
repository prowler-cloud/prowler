from pydantic import BaseModel
from prowler.providers.opennebula.lib.service.service import OpennebulaService
from prowler.lib.logger import logger

class TemplateService(OpennebulaService):
    def __init__(self, provider):
        super().__init__(provider)
        self.templates: list[Template] = []
        self.__get_templates__()

    def __get_templates__(self):
        try:
            template_pool = self.client.templatepool.info(-2, -1, -1, -1)
            for tmpl in template_pool.VMTEMPLATE:
                context = {}
                user_inputs = {}
                os_data = {}
                template_raw = tmpl.TEMPLATE._attributes if hasattr(tmpl.TEMPLATE, "_attributes") else {}

                if hasattr(tmpl.TEMPLATE, "CONTEXT"):
                    context = tmpl.TEMPLATE.CONTEXT._attributes if hasattr(tmpl.TEMPLATE.CONTEXT, "_attributes") else {}

                if hasattr(tmpl.TEMPLATE, "USER_INPUTS"):
                    user_inputs = tmpl.TEMPLATE.USER_INPUTS._attributes if hasattr(tmpl.TEMPLATE.USER_INPUTS, "_attributes") else {}

                if hasattr(tmpl.TEMPLATE, "OS"):
                    os_data = tmpl.TEMPLATE.OS._attributes if hasattr(tmpl.TEMPLATE.OS, "_attributes") else {}

                self.templates.append(Template(
                    id=tmpl.ID,
                    name=tmpl.NAME,
                    uname=tmpl.UNAME,
                    gname=tmpl.GNAME,
                    context=context,
                    user_inputs=user_inputs,
                    os=os_data,
                    template_raw=template_raw
                ))
        except Exception as error:
            logger.error(f"Error al obtener plantillas de VM: {error}")

class Template(BaseModel):
    id: str
    name: str
    uname: str
    gname: str
    context: dict
    user_inputs: dict
    os: dict
    template_raw: dict


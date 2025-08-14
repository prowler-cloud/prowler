import warnings

from dashboard.common_methods import get_section_containers_cis

warnings.filterwarnings("ignore")


def get_table(data):
    aux = data[
        [
            "REQUIREMENTS_ID",
            "REQUIREMENTS_DESCRIPTION",
            "REQUIREMENTS_ATTRIBUTES_SECTION",
            "CHECKID",
            "STATUS",
            "REGION",
            "ACCOUNTID",
            "RESOURCEID",
        ]
    ].copy()

    # Shorten the long FedRAMP KSI descriptions for better display
    ksi_short_names = {
        "A secure cloud service offering will protect user data, control access, and apply zero trust principles": "Identity and Access Management",
        "A secure cloud service offering will use cloud native architecture and design principles to enforce and enhance the Confidentiality, Integrity and Availability of the system": "Cloud Native Architecture",
        "A secure cloud service provider will ensure that all system changes are properly documented and configuration baselines are updated accordingly": "Change Management",
        "A secure cloud service provider will continuously educate their employees on cybersecurity measures, testing them regularly": "Cybersecurity Education",
        "A secure cloud service offering will document, report, and analyze security incidents to ensure regulatory compliance and continuous security improvement": "Incident Reporting",
        "A secure cloud service offering will monitor, log, and audit all important events, activity, and changes": "Monitoring, Logging, and Auditing",
        "A secure cloud service offering will have intentional, organized, universal guidance for how every information resource, including personnel, is secured": "Policy and Inventory",
        "A secure cloud service offering will define, maintain, and test incident response plan(s) and recovery capabilities to ensure minimal service disruption and data loss": "Recovery Planning",
        "A secure cloud service offering will follow FedRAMP encryption policies, continuously verify information resource integrity, and restrict access to third-party information resources": "Service Configuration",
        "A secure cloud service offering will understand, monitor, and manage supply chain risks from third-party information resources": "Third-Party Information Resources",
    }

    # Replace long descriptions with short names - use contains for partial matching
    if not aux.empty:
        for long_desc, short_name in ksi_short_names.items():
            mask = aux["REQUIREMENTS_DESCRIPTION"].str.contains(
                long_desc[:50], na=False, regex=False
            )
            aux.loc[mask, "REQUIREMENTS_DESCRIPTION"] = short_name

    return get_section_containers_cis(
        aux, "REQUIREMENTS_ID", "REQUIREMENTS_ATTRIBUTES_SECTION"
    )

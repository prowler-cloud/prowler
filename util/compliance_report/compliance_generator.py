import requests
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer


def generate_compliance_report(
    scan_id: str, compliance_id: str, output_path: str, email: str, password: str
):
    """
    Generate a PDF compliance report based on Prowler endpoints.

    Parameters:
    - scan_id: ID of the scan executed by Prowler.
    - compliance_id: ID of the compliance framework (e.g., "nis2_azure").
    - output_path: Output PDF file path (e.g., "compliance_report.pdf").
    - email: Email for the API authentication.
    - password: Password for the API.
    """
    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    h1 = styles["Heading1"]
    h2 = styles["Heading2"]
    h3 = styles["Heading3"]
    normal = styles["Normal"]

    # Call to this endpoint to get the credentials
    url_credentials = "http://localhost:8080/api/v1/tokens"
    payload = {
        "data": {
            "type": "tokens",
            "attributes": {
                "email": email,
                "password": password,
            },
        }
    }
    resp_credentials = requests.post(
        url_credentials,
        json=payload,
        headers={"Content-Type": "application/vnd.api+json"},
    ).json()
    token = resp_credentials.get("data", {}).get("attributes", {}).get("access")

    url_reqs = f"http://localhost:8080/api/v1/compliance-overviews/requirements?filter[compliance_id]={compliance_id}&filter[scan_id]={scan_id}"
    resp_reqs = (
        requests.get(url_reqs, headers={"Authorization": f"Bearer {token}"})
        .json()
        .get("data", [])
    )

    url_attrs = f"http://localhost:8080/api/v1/compliance-overviews/attributes?filter[compliance_id]={compliance_id}"
    resp_attrs = (
        requests.get(url_attrs, headers={"Authorization": f"Bearer {token}"})
        .json()
        .get("data", [])
    )

    compliance_name = resp_reqs[0]["attributes"]["framework"]
    compliance_version = resp_reqs[0]["attributes"]["version"]

    attrs_map = {item["id"]: item["attributes"] for item in resp_attrs}

    def get_finding_info(check_id: str):
        url_find = f"http://localhost:8080/api/v1/findings?filter[check_id]={check_id}&filter[scan_id]={scan_id}"
        value = (
            requests.get(url_find, headers={"Authorization": f"Bearer {token}"})
            .json()
            .get("data", [])
        )
        return value

    doc = SimpleDocTemplate(output_path, pagesize=letter)
    elements = []

    try:
        logo = Image(
            "util/compliance_report/assets/img/prowler_logo.png",
            width=5 * inch,
            height=1 * inch,
        )
        elements.append(logo)
    except Exception:
        pass
    elements.append(Spacer(1, 0.5 * inch))
    elements.append(Paragraph("Compliance Report - Prowler", title_style))
    elements.append(Spacer(1, 0.2 * inch))
    elements.append(Paragraph(f"Compliance ID: <b>{compliance_id}</b>", normal))
    elements.append(Paragraph(f"Scan ID: <b>{scan_id}</b>", normal))
    elements.append(Paragraph(f"Compliance Name: <b>{compliance_name}</b>", normal))
    elements.append(
        Paragraph(f"Compliance Version: <b>{compliance_version}</b>", normal)
    )
    elements.append(PageBreak())

    elements.append(Paragraph("Requirements Index", h1))

    # Organize requirements by section and subsection
    sections = {}
    for req in resp_attrs:
        meta = req["attributes"]["attributes"]["metadata"][0]
        section = meta["Section"]
        subsection = meta["SubSection"]
        req_id = req["id"]
        title = meta["Title"]

        if section not in sections:
            sections[section] = {}
        if subsection not in sections[section]:
            sections[section][subsection] = []

        sections[section][subsection].append({"id": req_id, "title": title})

    # Generate hierarchical index
    section_num = 1
    for section_name, subsections in sections.items():
        elements.append(Paragraph(f"{section_num}. {section_name}", h2))

        subsection_num = 1
        for subsection_name, requirements in subsections.items():
            elements.append(Paragraph(f"{subsection_name}", h3))

            req_num = 1
            for req in requirements:
                elements.append(Paragraph(f"{req['id']} - {req['title']}", normal))
                req_num += 1

            subsection_num += 1

        section_num += 1
        elements.append(Spacer(1, 0.1 * inch))

    elements.append(PageBreak())

    for req in resp_reqs:
        req_id = req["id"]
        attr = attrs_map.get(req_id, {})
        desc = req["attributes"]["description"]
        status = req["attributes"]["status"]

        elements.append(Paragraph(f"{req_id}: {attr.get('description', desc)}", h1))
        elements.append(Paragraph(f"State: <b>{status}</b>", normal))
        elements.append(Spacer(1, 0.1 * inch))

        metadata = attr.get("attributes", {}).get("metadata", [])
        if metadata:
            m = metadata[0]
            elements.append(
                Paragraph(f"Descripción: {m.get('AttributeDescription')}", normal)
            )
            elements.append(
                Paragraph(f"Nivel de Riesgo: {m.get('LevelOfRisk')}", normal)
            )
            elements.append(Paragraph(f"Peso: {m.get('Weight')}", normal))
            elements.append(Spacer(1, 0.1 * inch))

        checks = attr.get("attributes", {}).get("check_ids", [])
        for cid in checks:
            elements.append(Paragraph(f"Check: {cid}", h2))
            finds = get_finding_info(cid)
            if not finds:
                elements.append(Paragraph("- Sin findings para este check.", normal))
            else:
                for f in finds:
                    fid = f.get("id")
                    resource = f.get("attributes", {}).get("resource_id", "")
                    message = f.get("attributes", {}).get("message", "")
                    elements.append(
                        Paragraph(f"- [{fid}] {resource}: {message}", normal)
                    )
            elements.append(Spacer(1, 0.1 * inch))

        elements.append(PageBreak())

    doc.build(elements)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate a PDF compliance report with Prowler"
    )
    parser.add_argument("--scan-id", required=True, help="Scan ID")
    parser.add_argument("--compliance-id", required=True, help="Compliance ID")
    parser.add_argument(
        "--output", default="compliance_report.pdf", help="Output PDF file path"
    )
    parser.add_argument("--email", required=True, help="Email for the API")
    parser.add_argument("--password", required=True, help="Password for the API")
    args = parser.parse_args()

    generate_compliance_report(
        args.scan_id, args.compliance_id, args.output, args.email, args.password
    )

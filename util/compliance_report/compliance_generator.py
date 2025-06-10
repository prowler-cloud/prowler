import requests
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


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

    def create_risk_component(risk_level, weight, score=0):
        """Create a visual risk component similar to the UI design"""
        # Define colors based on risk level
        if risk_level >= 4:
            risk_color = colors.Color(0.8, 0.2, 0.2)  # Red
        elif risk_level >= 3:
            risk_color = colors.Color(0.9, 0.6, 0.2)  # Orange
        elif risk_level >= 2:
            risk_color = colors.Color(0.9, 0.9, 0.2)  # Yellow
        else:
            risk_color = colors.Color(0.2, 0.8, 0.2)  # Green

        # Weight color (green for high values)
        if weight >= 100:
            weight_color = colors.Color(0.2, 0.8, 0.2)  # Green
        elif weight >= 50:
            weight_color = colors.Color(0.9, 0.9, 0.2)  # Yellow
        else:
            weight_color = colors.Color(0.8, 0.2, 0.2)  # Red

        # Score color (gray for 0)
        score_color = colors.Color(0.4, 0.4, 0.4)  # Gray

        # Create table data
        data = [
            [
                "Risk Level:",
                str(risk_level),
                "Weight:",
                str(weight),
                "Score:",
                str(score),
            ]
        ]

        # Create table
        table = Table(
            data,
            colWidths=[
                0.8 * inch,
                0.4 * inch,
                0.6 * inch,
                0.4 * inch,
                0.5 * inch,
                0.4 * inch,
            ],
        )

        # Apply styling
        table.setStyle(
            TableStyle(
                [
                    # Risk Level styling
                    ("BACKGROUND", (0, 0), (0, 0), colors.Color(0.9, 0.9, 0.9)),
                    ("BACKGROUND", (1, 0), (1, 0), risk_color),
                    ("TEXTCOLOR", (1, 0), (1, 0), colors.white),
                    ("FONTNAME", (1, 0), (1, 0), "Helvetica-Bold"),
                    # Weight styling
                    ("BACKGROUND", (2, 0), (2, 0), colors.Color(0.9, 0.9, 0.9)),
                    ("BACKGROUND", (3, 0), (3, 0), weight_color),
                    ("TEXTCOLOR", (3, 0), (3, 0), colors.white),
                    ("FONTNAME", (3, 0), (3, 0), "Helvetica-Bold"),
                    # Score styling
                    ("BACKGROUND", (4, 0), (4, 0), colors.Color(0.9, 0.9, 0.9)),
                    ("BACKGROUND", (5, 0), (5, 0), score_color),
                    ("TEXTCOLOR", (5, 0), (5, 0), colors.white),
                    ("FONTNAME", (5, 0), (5, 0), "Helvetica-Bold"),
                    # General styling
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )

        return table

    def create_status_component(status):
        """Create a visual status component with colors"""
        # Define colors based on status
        if status.upper() == "PASS":
            status_color = colors.Color(0.2, 0.8, 0.2)  # Green
        elif status.upper() == "FAIL":
            status_color = colors.Color(0.8, 0.2, 0.2)  # Red
        else:
            status_color = colors.Color(0.4, 0.4, 0.4)  # Gray for unknown status

        # Create table data
        data = [["State:", status.upper()]]

        # Create table
        table = Table(data, colWidths=[0.6 * inch, 0.8 * inch])

        # Apply styling
        table.setStyle(
            TableStyle(
                [
                    # Label styling
                    ("BACKGROUND", (0, 0), (0, 0), colors.Color(0.9, 0.9, 0.9)),
                    ("FONTNAME", (0, 0), (0, 0), "Helvetica"),
                    # Status styling
                    ("BACKGROUND", (1, 0), (1, 0), status_color),
                    ("TEXTCOLOR", (1, 0), (1, 0), colors.white),
                    ("FONTNAME", (1, 0), (1, 0), "Helvetica-Bold"),
                    # General styling
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("FONTSIZE", (0, 0), (-1, -1), 12),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ]
            )
        )

        return table

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

        # Create visual status component
        status_component = create_status_component(status)
        elements.append(status_component)
        elements.append(Spacer(1, 0.1 * inch))

        metadata = attr.get("attributes", {}).get("metadata", [])
        if metadata:
            m = metadata[0]
            elements.append(
                Paragraph(f"Description: {m.get('AttributeDescription')}", normal)
            )
            elements.append(Spacer(1, 0.1 * inch))

            # Create visual risk component
            risk_level = m.get("LevelOfRisk", 0)
            weight = m.get("Weight", 0)
            score = m.get("Score", 0)

            risk_component = create_risk_component(risk_level, weight, score)
            elements.append(risk_component)
            elements.append(Spacer(1, 0.1 * inch))

        checks = attr.get("attributes", {}).get("check_ids", [])
        for cid in checks:
            elements.append(Paragraph(f"Check: {cid}", h2))
            finds = get_finding_info(cid)
            if not finds:
                elements.append(Paragraph("- No", normal))
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

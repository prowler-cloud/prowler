import io

import matplotlib.pyplot as plt
import requests
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
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
    scan_id: str,
    compliance_id: str,
    output_path: str,
    email: str,
    password: str,
    only_failed: bool = False,
):
    """
    Generate a PDF compliance report based on Prowler endpoints.

    Parameters:
    - scan_id: ID of the scan executed by Prowler.
    - compliance_id: ID of the compliance framework (e.g., "nis2_azure").
    - output_path: Output PDF file path (e.g., "compliance_report.pdf").
    - email: Email for the API authentication.
    - password: Password for the API.
    - only_failed: If True, only requirements with status "FAIL" will be included in the list of requirements.
    """
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Title"],
        fontSize=24,
        textColor=colors.Color(0.1, 0.2, 0.4),
        spaceAfter=20,
        fontName="Helvetica-Bold",
        alignment=TA_CENTER,
    )

    h1 = ParagraphStyle(
        "CustomH1",
        parent=styles["Heading1"],
        fontSize=18,
        textColor=colors.Color(0.2, 0.4, 0.6),
        spaceBefore=20,
        spaceAfter=12,
        fontName="Helvetica-Bold",
        leftIndent=0,
        borderWidth=2,
        borderColor=colors.Color(0.2, 0.4, 0.6),
        borderPadding=8,
        backColor=colors.Color(0.95, 0.97, 1.0),
    )

    h2 = ParagraphStyle(
        "CustomH2",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=colors.Color(0.3, 0.5, 0.7),
        spaceBefore=15,
        spaceAfter=8,
        fontName="Helvetica-Bold",
        leftIndent=10,
        borderWidth=1,
        borderColor=colors.Color(0.7, 0.8, 0.9),
        borderPadding=5,
        backColor=colors.Color(0.98, 0.99, 1.0),
    )

    h3 = ParagraphStyle(
        "CustomH3",
        parent=styles["Heading3"],
        fontSize=12,
        textColor=colors.Color(0.4, 0.6, 0.8),
        spaceBefore=10,
        spaceAfter=6,
        fontName="Helvetica-Bold",
        leftIndent=20,
    )

    normal = ParagraphStyle(
        "CustomNormal",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.Color(0.2, 0.2, 0.2),
        spaceBefore=4,
        spaceAfter=4,
        leftIndent=30,
        fontName="Helvetica",
    )

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
        if risk_level >= 4:
            risk_color = colors.Color(0.8, 0.2, 0.2)
        elif risk_level >= 3:
            risk_color = colors.Color(0.9, 0.6, 0.2)
        elif risk_level >= 2:
            risk_color = colors.Color(0.9, 0.9, 0.2)
        else:
            risk_color = colors.Color(0.2, 0.8, 0.2)

        if weight <= 50:
            weight_color = colors.Color(0.2, 0.8, 0.2)
        elif weight <= 100:
            weight_color = colors.Color(0.9, 0.9, 0.2)
        else:
            weight_color = colors.Color(0.8, 0.2, 0.2)

        score_color = colors.Color(0.4, 0.4, 0.4)

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

        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, 0), colors.Color(0.9, 0.9, 0.9)),
                    ("BACKGROUND", (1, 0), (1, 0), risk_color),
                    ("TEXTCOLOR", (1, 0), (1, 0), colors.white),
                    ("FONTNAME", (1, 0), (1, 0), "Helvetica-Bold"),
                    ("BACKGROUND", (2, 0), (2, 0), colors.Color(0.9, 0.9, 0.9)),
                    ("BACKGROUND", (3, 0), (3, 0), weight_color),
                    ("TEXTCOLOR", (3, 0), (3, 0), colors.white),
                    ("FONTNAME", (3, 0), (3, 0), "Helvetica-Bold"),
                    ("BACKGROUND", (4, 0), (4, 0), colors.Color(0.9, 0.9, 0.9)),
                    ("BACKGROUND", (5, 0), (5, 0), score_color),
                    ("TEXTCOLOR", (5, 0), (5, 0), colors.white),
                    ("FONTNAME", (5, 0), (5, 0), "Helvetica-Bold"),
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
        if status.upper() == "PASS":
            status_color = colors.Color(0.2, 0.8, 0.2)
        elif status.upper() == "FAIL":
            status_color = colors.Color(0.8, 0.2, 0.2)
        else:
            status_color = colors.Color(0.4, 0.4, 0.4)

        data = [["State:", status.upper()]]

        table = Table(data, colWidths=[0.6 * inch, 0.8 * inch])

        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, 0), colors.Color(0.9, 0.9, 0.9)),
                    ("FONTNAME", (0, 0), (0, 0), "Helvetica"),
                    ("BACKGROUND", (1, 0), (1, 0), status_color),
                    ("TEXTCOLOR", (1, 0), (1, 0), colors.white),
                    ("FONTNAME", (1, 0), (1, 0), "Helvetica-Bold"),
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

    def create_section_score_chart(resp_reqs, attrs_map):
        """Create a bar chart showing compliance score by section"""
        sections_data = {}

        for req in resp_reqs:
            req_id = req["id"]
            attr = attrs_map.get(req_id, {})
            status = req["attributes"]["status"]

            metadata = attr.get("attributes", {}).get("metadata", [])
            if metadata:
                m = metadata[0]
                section = m.get("Section", "Unknown")
                risk_level = m.get("LevelOfRisk", 0)
                weight = m.get("Weight", 0)

                if section not in sections_data:
                    sections_data[section] = {"total_score": 0, "max_possible_score": 0}

                max_score = risk_level * weight
                sections_data[section]["max_possible_score"] += max_score

                if status == "PASS":
                    sections_data[section]["total_score"] += max_score

        section_names = []
        compliance_percentages = []

        for section, data in sections_data.items():
            if data["max_possible_score"] > 0:
                compliance_percentage = (
                    data["total_score"] / data["max_possible_score"]
                ) * 100
            else:
                compliance_percentage = 0

            section_names.append(section)
            compliance_percentages.append(compliance_percentage)

        sorted_data = sorted(
            zip(section_names, compliance_percentages), key=lambda x: x[1], reverse=True
        )
        section_names, compliance_percentages = (
            zip(*sorted_data) if sorted_data else ([], [])
        )

        fig, ax = plt.subplots(figsize=(12, 8))

        colors_list = []
        for percentage in compliance_percentages:
            if percentage >= 80:
                color = "#4CAF50"
            elif percentage >= 60:
                color = "#8BC34A"
            elif percentage >= 40:
                color = "#FFEB3B"
            elif percentage >= 20:
                color = "#FF9800"
            else:
                color = "#F44336"
            colors_list.append(color)

        bars = ax.bar(section_names, compliance_percentages, color=colors_list)

        ax.set_ylabel("Compliance Score (%)", fontsize=12)
        ax.set_xlabel("Section", fontsize=12)
        ax.set_title("COMPLIANCE SCORE BY SECTIONS", fontsize=14, fontweight="bold")
        ax.set_ylim(0, 100)

        for bar, percentage in zip(bars, compliance_percentages):
            height = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width() / 2.0,
                height + 1,
                f"{percentage:.1f}%",
                ha="center",
                va="bottom",
                fontweight="bold",
            )

        plt.xticks(rotation=45, ha="right")

        ax.grid(True, alpha=0.3, axis="y")

        plt.tight_layout()

        buffer = io.BytesIO()
        plt.savefig(buffer, format="png", dpi=300, bbox_inches="tight")
        buffer.seek(0)
        plt.close()

        return buffer

    def get_finding_info(check_id: str):
        url_find = f"http://localhost:8080/api/v1/findings?filter[check_id]={check_id}&filter[scan_id]={scan_id}"
        value = (
            requests.get(url_find, headers={"Authorization": f"Bearer {token}"})
            .json()
            .get("data", [])
        )
        return value

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        title=f"Compliance Report - {compliance_name}",
        author="Prowler",
        subject=f"Compliance Report for {compliance_name}",
        creator="Prowler Compliance Generator",
        keywords=f"compliance,{compliance_name},security,framework,prowler",
    )
    elements = []

    try:
        logo = Image(
            "util/compliance_report/assets/img/prowler_logo.png",
            width=5 * inch,
            height=0.8 * inch,
        )
        elements.append(logo)
    except Exception:
        pass
    elements.append(Spacer(1, 0.3 * inch))
    elements.append(Paragraph("Compliance Report - Prowler", title_style))
    elements.append(Spacer(1, 0.3 * inch))

    info_data = [
        ["Compliance Framework:", compliance_name],
        ["Compliance ID:", compliance_id],
        ["Version:", compliance_version],
        ["Scan ID:", scan_id],
    ]

    info_table = Table(info_data, colWidths=[2 * inch, 4 * inch])
    info_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.Color(0.2, 0.4, 0.6)),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("BACKGROUND", (1, 0), (1, -1), colors.Color(0.95, 0.97, 1.0)),
                ("TEXTCOLOR", (1, 0), (1, -1), colors.Color(0.2, 0.2, 0.2)),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("FONTSIZE", (0, 0), (-1, -1), 11),
                ("GRID", (0, 0), (-1, -1), 1, colors.Color(0.7, 0.8, 0.9)),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )

    elements.append(info_table)
    elements.append(Spacer(1, 0.2 * inch))
    elements.append(PageBreak())

    elements.append(Paragraph("Requirements Index", h1))

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

    elements.append(Paragraph("Compliance Score by Sections", h1))
    elements.append(Spacer(1, 0.2 * inch))

    chart_buffer = create_section_score_chart(resp_reqs, attrs_map)
    chart_image = Image(chart_buffer, width=7 * inch, height=5.5 * inch)
    elements.append(chart_image)

    total_score = 0
    max_possible_score = 0

    for req in resp_reqs:
        req_id = req["id"]
        attr = attrs_map.get(req_id, {})
        status = req["attributes"]["status"]

        metadata = attr.get("attributes", {}).get("metadata", [])
        if metadata:
            m = metadata[0]
            risk_level = m.get("LevelOfRisk", 0)
            weight = m.get("Weight", 0)
            max_score = risk_level * weight
            max_possible_score += max_score

            if status == "PASS":
                total_score += max_score

    overall_compliance = (
        (total_score / max_possible_score * 100) if max_possible_score > 0 else 0
    )

    elements.append(Spacer(1, 0.3 * inch))

    summary_data = [
        ["Total Score:", f"{total_score:,}"],
        ["Max Possible Score:", f"{max_possible_score:,}"],
        ["Overall Compliance:", f"{overall_compliance:.2f}%"],
    ]

    if overall_compliance >= 80:
        compliance_color = colors.Color(0.2, 0.8, 0.2)
    elif overall_compliance >= 60:
        compliance_color = colors.Color(0.8, 0.8, 0.2)
    else:
        compliance_color = colors.Color(0.8, 0.2, 0.2)

    summary_table = Table(summary_data, colWidths=[2.5 * inch, 2 * inch])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 1), colors.Color(0.3, 0.5, 0.7)),
                ("TEXTCOLOR", (0, 0), (0, 1), colors.white),
                ("FONTNAME", (0, 0), (0, 1), "Helvetica-Bold"),
                ("BACKGROUND", (0, 2), (0, 2), colors.Color(0.1, 0.3, 0.5)),
                ("TEXTCOLOR", (0, 2), (0, 2), colors.white),
                ("FONTNAME", (0, 2), (0, 2), "Helvetica-Bold"),
                ("FONTSIZE", (0, 2), (0, 2), 12),
                ("BACKGROUND", (1, 0), (1, 1), colors.Color(0.95, 0.97, 1.0)),
                ("TEXTCOLOR", (1, 0), (1, 1), colors.Color(0.2, 0.2, 0.2)),
                ("FONTNAME", (1, 0), (1, 1), "Helvetica"),
                ("BACKGROUND", (1, 2), (1, 2), compliance_color),
                ("TEXTCOLOR", (1, 2), (1, 2), colors.white),
                ("FONTNAME", (1, 2), (1, 2), "Helvetica-Bold"),
                ("FONTSIZE", (1, 2), (1, 2), 14),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("FONTSIZE", (0, 0), (1, 1), 11),
                ("GRID", (0, 0), (-1, -1), 1.5, colors.Color(0.5, 0.6, 0.7)),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )

    elements.append(summary_table)

    elements.append(PageBreak())

    def get_weight(req):
        req_id = req["id"]
        attr = attrs_map.get(req_id, {})
        metadata = attr.get("attributes", {}).get("metadata", [])
        if metadata:
            return metadata[0].get("Weight", 0)
        return 0

    sorted_reqs = sorted(resp_reqs, key=get_weight, reverse=True)

    if only_failed:
        sorted_reqs = [
            req for req in sorted_reqs if req["attributes"]["status"] == "FAIL"
        ]

    for req in sorted_reqs:
        req_id = req["id"]
        attr = attrs_map.get(req_id, {})
        desc = req["attributes"]["description"]
        status = req["attributes"]["status"]

        elements.append(Paragraph(f"{req_id}: {attr.get('description', desc)}", h1))

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

            risk_level = m.get("LevelOfRisk", 0)
            weight = m.get("Weight", 0)

            if status == "PASS":
                score = risk_level * weight
            else:
                score = 0

            risk_component = create_risk_component(risk_level, weight, score)
            elements.append(risk_component)
            elements.append(Spacer(1, 0.1 * inch))

        checks = attr.get("attributes", {}).get("check_ids", [])
        for cid in checks:
            elements.append(Paragraph(f"Check: {cid}", h2))
            finds = get_finding_info(cid)
            if not finds:
                elements.append(
                    Paragraph("- No information for this finding currently", normal)
                )
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
    parser.add_argument(
        "--only-failed",
        action="store_true",
        help="Only include failed requirements in the list of requirements",
    )
    args = parser.parse_args()

    generate_compliance_report(
        args.scan_id,
        args.compliance_id,
        args.output,
        args.email,
        args.password,
        args.only_failed,
    )

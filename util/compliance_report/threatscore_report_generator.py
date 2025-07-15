import io
import os

import matplotlib.pyplot as plt
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from api.models import Finding, Provider
from api.utils import initialize_prowler_provider
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.finding import Finding as FindingOutput

pdfmetrics.registerFont(
    TTFont(
        "PlusJakartaSans",
        os.path.join(
            os.path.dirname(__file__), "assets/fonts/PlusJakartaSans-Regular.ttf"
        ),
    )
)

pdfmetrics.registerFont(
    TTFont(
        "FiraCode",
        os.path.join(os.path.dirname(__file__), "assets/fonts/FiraCode-Regular.ttf"),
    )
)


def generate_threatscore_report(
    scan_id: str,
    compliance_id: str,
    output_path: str,
    provider_id: str,
    tenant_id: str,
    only_failed: bool = True,
    min_risk_level: int = 4,
):
    """
    Generate a PDF compliance report based on Prowler ORM objects.

    Parameters:
    - scan_id: ID of the scan executed by Prowler.
    - compliance_id: ID of the compliance framework (e.g., "nis2_azure").
    - output_path: Output PDF file path (e.g., "threatscore_report.pdf").
    - provider_id: Provider ID for the scan.
    - tenant_id: Tenant ID for the scan.
    - only_failed: If True, only requirements with status "FAIL" will be included in the list of requirements.
    - min_risk_level: Minimum risk level for critical failed requirements.
    """
    styles = getSampleStyleSheet()

    prowler_dark_green = colors.Color(0.1, 0.5, 0.2)

    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Title"],
        fontSize=24,
        textColor=prowler_dark_green,
        spaceAfter=20,
        fontName="PlusJakartaSans",
        alignment=TA_CENTER,
    )

    h1 = ParagraphStyle(
        "CustomH1",
        parent=styles["Heading1"],
        fontSize=18,
        textColor=colors.Color(0.2, 0.4, 0.6),
        spaceBefore=20,
        spaceAfter=12,
        fontName="PlusJakartaSans",
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
        fontName="PlusJakartaSans",
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
        fontName="PlusJakartaSans",
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
        fontName="PlusJakartaSans",
    )

    normal_center = ParagraphStyle(
        "CustomNormalCenter",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.Color(0.2, 0.2, 0.2),
        fontName="PlusJakartaSans",
    )

    provider_obj = Provider.objects.get(id=provider_id)
    prowler_provider = initialize_prowler_provider(provider_obj)
    provider_type = provider_obj.provider

    frameworks_bulk = Compliance.get_bulk(provider_type)
    compliance_obj = frameworks_bulk[compliance_id]
    compliance_name = compliance_obj.name
    compliance_version = getattr(compliance_obj, "Version", "N/A")
    compliance_description = getattr(compliance_obj, "Description", "")

    findings_qs = Finding.all_objects.filter(scan_id=scan_id).order_by("uid")
    findings = [
        FindingOutput.transform_api_finding(f, prowler_provider) for f in findings_qs
    ]

    attrs_map = {}
    resp_reqs = []
    resp_attrs = []
    for req_id, req in compliance_obj.requirements.items():
        attrs_map[req_id] = {
            "id": req_id,
            "attributes": {
                "metadata": [req.metadata],
                "check_ids": req.check_ids,
            },
            "description": getattr(req, "description", ""),
        }
        resp_attrs.append(
            {
                "id": req_id,
                "attributes": {
                    "framework_description": compliance_description,
                    "attributes": {"metadata": [req.metadata]},
                },
            }
        )
        status = "UNKNOWN"
        description = getattr(req, "description", "")
        for f in findings:
            if f["check_id"] in req.check_ids:
                status = f["status"]
                description = f.get("description", description)
                break
        resp_reqs.append(
            {
                "id": req_id,
                "attributes": {
                    "framework": compliance_name,
                    "version": compliance_version,
                    "status": status,
                    "description": description,
                },
            }
        )

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
                    ("FONTNAME", (1, 0), (1, 0), "FiraCode"),
                    ("BACKGROUND", (2, 0), (2, 0), colors.Color(0.9, 0.9, 0.9)),
                    ("BACKGROUND", (3, 0), (3, 0), weight_color),
                    ("TEXTCOLOR", (3, 0), (3, 0), colors.white),
                    ("FONTNAME", (3, 0), (3, 0), "FiraCode"),
                    ("BACKGROUND", (4, 0), (4, 0), colors.Color(0.9, 0.9, 0.9)),
                    ("BACKGROUND", (5, 0), (5, 0), score_color),
                    ("TEXTCOLOR", (5, 0), (5, 0), colors.white),
                    ("FONTNAME", (5, 0), (5, 0), "FiraCode"),
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

        elements.append(Spacer(1, 0.1 * inch))

        table = Table(data, colWidths=[0.6 * inch, 0.8 * inch])

        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, 0), colors.Color(0.9, 0.9, 0.9)),
                    ("FONTNAME", (0, 0), (0, 0), "PlusJakartaSans"),
                    ("BACKGROUND", (1, 0), (1, 0), status_color),
                    ("TEXTCOLOR", (1, 0), (1, 0), colors.white),
                    ("FONTNAME", (1, 0), (1, 0), "FiraCode"),
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
        return [f for f in findings if f["check_id"] == check_id]

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        title=f"Prowler ThreatScore Report - {compliance_name}",
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
    elements.append(Spacer(1, 0.5 * inch))
    elements.append(Paragraph("Prowler ThreatScore Report", title_style))
    elements.append(Spacer(1, 0.5 * inch))

    info_data = [
        ["Compliance Framework:", compliance_name],
        ["Compliance ID:", compliance_id],
        ["Version:", compliance_version],
        ["Scan ID:", scan_id],
        ["Description:", Paragraph(compliance_description, normal_center)],
    ]
    info_table = Table(info_data, colWidths=[2 * inch, 4 * inch])
    info_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 4), colors.Color(0.2, 0.4, 0.6)),
                ("TEXTCOLOR", (0, 0), (0, 4), colors.white),
                ("FONTNAME", (0, 0), (0, 4), "FiraCode"),
                ("BACKGROUND", (1, 0), (1, 4), colors.Color(0.95, 0.97, 1.0)),
                ("TEXTCOLOR", (1, 0), (1, 4), colors.Color(0.2, 0.2, 0.2)),
                ("FONTNAME", (1, 0), (1, 4), "PlusJakartaSans"),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
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
                ("FONTNAME", (0, 0), (0, 1), "FiraCode"),
                ("BACKGROUND", (0, 2), (0, 2), colors.Color(0.1, 0.3, 0.5)),
                ("TEXTCOLOR", (0, 2), (0, 2), colors.white),
                ("FONTNAME", (0, 2), (0, 2), "FiraCode"),
                ("FONTSIZE", (0, 2), (0, 2), 12),
                ("BACKGROUND", (1, 0), (1, 1), colors.Color(0.95, 0.97, 1.0)),
                ("TEXTCOLOR", (1, 0), (1, 1), colors.Color(0.2, 0.2, 0.2)),
                ("FONTNAME", (1, 0), (1, 1), "PlusJakartaSans"),
                ("BACKGROUND", (1, 2), (1, 2), compliance_color),
                ("TEXTCOLOR", (1, 2), (1, 2), colors.white),
                ("FONTNAME", (1, 2), (1, 2), "FiraCode"),
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

    elements.append(Paragraph("Top Requirements by Level of Risk", h1))
    elements.append(Spacer(1, 0.1 * inch))
    elements.append(
        Paragraph(f"Critical Failed Requirements (Risk Level ≥ {min_risk_level})", h2)
    )
    elements.append(Spacer(1, 0.2 * inch))

    critical_reqs = []
    for req in resp_reqs:
        req_id = req["id"]
        attr = attrs_map.get(req_id, {})
        status = req["attributes"]["status"]

        if status == "FAIL":
            metadata = attr.get("attributes", {}).get("metadata", [])
            if metadata:
                m = metadata[0]
                risk_level = m.get("LevelOfRisk", 0)
                weight = m.get("Weight", 0)

                if risk_level >= min_risk_level:
                    critical_reqs.append(
                        {
                            "req": req,
                            "attr": attr,
                            "risk_level": risk_level,
                            "weight": weight,
                            "metadata": m,
                        }
                    )

    critical_reqs.sort(key=lambda x: (x["risk_level"], x["weight"]), reverse=True)

    if not critical_reqs:
        elements.append(
            Paragraph("✅ No critical failed requirements found. Great job!", normal)
        )
    else:
        elements.append(
            Paragraph(
                f"Found {len(critical_reqs)} critical failed requirements that require immediate attention:",
                normal,
            )
        )
        elements.append(Spacer(1, 0.5 * inch))

        table_data = [["Risk", "Weight", "Requirement ID", "Title", "Section"]]

        for idx, critical_req in enumerate(critical_reqs):
            req_id = critical_req["req"]["id"]
            risk_level = critical_req["risk_level"]
            weight = critical_req["weight"]
            title = critical_req["metadata"].get("Title", "N/A")
            section = critical_req["metadata"].get("Section", "N/A")

            if len(title) > 50:
                title = title[:47] + "..."

            table_data.append([str(risk_level), str(weight), req_id, title, section])

        critical_table = Table(
            table_data,
            colWidths=[0.6 * inch, 0.8 * inch, 1.2 * inch, 3 * inch, 1.4 * inch],
        )

        critical_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.Color(0.8, 0.2, 0.2)),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "FiraCode"),
                    ("FONTSIZE", (0, 0), (-1, 0), 10),
                    ("BACKGROUND", (0, 1), (0, -1), colors.Color(0.8, 0.2, 0.2)),
                    ("TEXTCOLOR", (0, 1), (0, -1), colors.white),
                    ("FONTNAME", (0, 1), (0, -1), "FiraCode"),
                    ("ALIGN", (0, 1), (0, -1), "CENTER"),
                    ("FONTSIZE", (0, 1), (0, -1), 12),
                    ("ALIGN", (1, 1), (1, -1), "CENTER"),
                    ("FONTNAME", (1, 1), (1, -1), "FiraCode"),
                    ("FONTNAME", (2, 1), (2, -1), "FiraCode"),
                    ("FONTSIZE", (2, 1), (2, -1), 9),
                    ("FONTNAME", (3, 1), (-1, -1), "PlusJakartaSans"),
                    ("FONTSIZE", (3, 1), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("GRID", (0, 0), (-1, -1), 1, colors.Color(0.7, 0.7, 0.7)),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("BACKGROUND", (1, 1), (-1, -1), colors.Color(0.98, 0.98, 0.98)),
                ]
            )
        )

        for idx, critical_req in enumerate(critical_reqs):
            row_idx = idx + 1
            weight = critical_req["weight"]

            if weight >= 150:
                weight_color = colors.Color(0.8, 0.2, 0.2)
            elif weight >= 100:
                weight_color = colors.Color(0.9, 0.6, 0.2)
            else:
                weight_color = colors.Color(0.9, 0.9, 0.2)

            critical_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (1, row_idx), (1, row_idx), weight_color),
                        ("TEXTCOLOR", (1, row_idx), (1, row_idx), colors.white),
                    ]
                )
            )

        elements.append(critical_table)
        elements.append(Spacer(1, 0.2 * inch))

        warning_text = """
        <b>IMMEDIATE ACTION REQUIRED:</b><br/>
        These requirements have the highest risk levels and have failed compliance checks.
        Please prioritize addressing these issues to improve your security posture.
        """

        warning_style = ParagraphStyle(
            "Warning",
            parent=styles["Normal"],
            fontSize=11,
            textColor=colors.Color(0.8, 0.2, 0.2),
            spaceBefore=10,
            spaceAfter=10,
            leftIndent=20,
            rightIndent=20,
            fontName="PlusJakartaSans",
            backColor=colors.Color(1.0, 0.95, 0.95),
            borderWidth=2,
            borderColor=colors.Color(0.8, 0.2, 0.2),
            borderPadding=10,
        )

        elements.append(Paragraph(warning_text, warning_style))

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
            elements.append(Paragraph("Title: ", h3))
            elements.append(Paragraph(f"{m.get('Title')}", normal))
            elements.append(Paragraph("Section: ", h3))
            elements.append(Paragraph(f"{m.get('Section')}", normal))
            elements.append(Paragraph("SubSection: ", h3))
            elements.append(Paragraph(f"{m.get('SubSection')}", normal))
            elements.append(Paragraph("Description: ", h3))
            elements.append(Paragraph(f"{m.get('AttributeDescription')}", normal))
            elements.append(Paragraph("Additional Information: ", h3))
            elements.append(Paragraph(f"{m.get('AdditionalInformation')}", normal))
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
            elements.append(Spacer(1, 0.1 * inch))
            finds = get_finding_info(cid)
            if not finds:
                elements.append(
                    Paragraph("- No information for this finding currently", normal)
                )
            else:
                findings_table_data = [
                    [
                        "Finding",
                        "Resource name",
                        "Severity",
                        "Status",
                        "Region",
                    ]
                ]
                for f in finds:
                    attr = f["attributes"]
                    check_meta = attr.get("check_metadata", {})
                    title = check_meta.get("checktitle", attr.get("check_id", ""))
                    resource_name = attr.get("resource_id")
                    if not resource_name:
                        rel_resources = (
                            f.get("relationships", {})
                            .get("resources", {})
                            .get("data", [])
                        )
                        if rel_resources and isinstance(rel_resources, list):
                            resource_name = rel_resources[0].get("id", "")
                        else:
                            resource_name = ""
                    severity = attr.get("severity", "").capitalize()
                    status = attr.get("status", "").upper()
                    region = attr.get("region", "global")

                    findings_table_data.append(
                        [
                            Paragraph(title, normal_center),
                            Paragraph(resource_name, normal_center),
                            Paragraph(severity, normal_center),
                            Paragraph(status, normal_center),
                            Paragraph(region, normal_center),
                        ]
                    )
                findings_table = Table(
                    findings_table_data,
                    colWidths=[
                        2.5 * inch,
                        3 * inch,
                        0.9 * inch,
                        0.9 * inch,
                        0.9 * inch,
                    ],
                )
                findings_table.setStyle(
                    TableStyle(
                        [
                            (
                                "BACKGROUND",
                                (0, 0),
                                (-1, 0),
                                colors.Color(0.2, 0.4, 0.6),
                            ),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                            ("FONTNAME", (0, 0), (-1, 0), "FiraCode"),
                            ("ALIGN", (0, 0), (0, 0), "CENTER"),
                            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                            ("FONTSIZE", (0, 0), (-1, -1), 9),
                            (
                                "GRID",
                                (0, 0),
                                (-1, -1),
                                0.1,
                                colors.Color(0.7, 0.8, 0.9),
                            ),
                            ("LEFTPADDING", (0, 0), (0, 0), 0),
                            ("RIGHTPADDING", (0, 0), (0, 0), 0),
                            ("TOPPADDING", (0, 0), (-1, -1), 4),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ]
                    )
                )
                elements.append(findings_table)
            elements.append(Spacer(1, 0.1 * inch))

        elements.append(PageBreak())

    def add_footer(canvas: canvas.Canvas, doc):
        width, height = doc.pagesize
        page_num_text = f"Page {doc.page}"
        canvas.setFont("PlusJakartaSans", 9)
        canvas.setFillColorRGB(0.4, 0.4, 0.4)
        canvas.drawString(30, 20, page_num_text)
        powered_text = "Powered by Prowler"
        text_width = canvas.stringWidth(powered_text, "PlusJakartaSans", 9)
        canvas.drawString(width - text_width - 30, 20, powered_text)

    doc.build(elements, onFirstPage=add_footer, onLaterPages=add_footer)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate a PDF compliance report with Prowler"
    )
    parser.add_argument("--scan-id", required=True, help="Scan ID")
    parser.add_argument("--compliance-id", required=True, help="Compliance ID")
    parser.add_argument(
        "--output", default="threatscore_report.pdf", help="Output PDF file path"
    )
    parser.add_argument("--provider-id", required=True, help="Provider ID")
    parser.add_argument("--tenant-id", required=True, help="Tenant ID")
    parser.add_argument(
        "--only-failed",
        action="store_true",
        help="Only include failed requirements in the list of requirements",
    )
    parser.add_argument(
        "--min-risk-level",
        type=int,
        default=4,
        help="Minimum risk level for critical failed requirements",
    )
    args = parser.parse_args()

    generate_threatscore_report(
        args.scan_id,
        args.compliance_id,
        args.output,
        args.provider_id,
        args.tenant_id,
        args.only_failed,
        args.min_risk_level,
    )

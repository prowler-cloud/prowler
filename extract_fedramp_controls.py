#!/usr/bin/env python3
"""
Script to extract FedRAMP Moderate Revision 5 controls from CSV file.
"""

import csv
import re
from collections import defaultdict

def parse_fedramp_csv(csv_file_path):
    """Parse the FedRAMP CSV file and extract controls with X markings."""
    
    controls_with_x = []
    
    with open(csv_file_path, 'r', encoding='utf-8-sig') as file:
        # Skip the header rows that don't contain actual control data
        lines = file.readlines()
        
        # Find where the actual data starts (after the header)
        data_start = 0
        for i, line in enumerate(lines):
            if line.startswith('AC-01,'):
                data_start = i
                break
        
        # Parse from the data start
        csv_reader = csv.reader(lines[data_start:])
        
        for row in csv_reader:
            if len(row) >= 9:  # Ensure we have enough columns
                sort_id = row[0].strip()
                family = row[1].strip()
                control_id = row[2].strip()
                control_name = row[3].strip()
                description = row[4].strip()
                discussion = row[5].strip()
                fedramp_params = row[6].strip()
                fedramp_guidance = row[7].strip()
                fedramp_parameter = row[8].strip() if len(row) > 8 else ""
                
                # Check if this control is marked with X in FedRAMP Parameter column
                if fedramp_parameter.strip() == 'X':
                    controls_with_x.append({
                        'sort_id': sort_id,
                        'family': family,
                        'control_id': control_id,
                        'control_name': control_name,
                        'description': description,
                        'discussion': discussion,
                        'fedramp_params': fedramp_params,
                        'fedramp_guidance': fedramp_guidance
                    })
    
    return controls_with_x

def group_by_family(controls):
    """Group controls by their family."""
    families = defaultdict(list)
    
    for control in controls:
        # Extract family from control_id (e.g., AC-1 -> AC)
        family_code = control['control_id'].split('-')[0]
        families[family_code].append(control)
    
    return dict(families)

def print_control_summary(controls):
    """Print a summary of the controls."""
    families = group_by_family(controls)
    
    print(f"FedRAMP Moderate Baseline Revision 5 - Controls with 'X' Parameter")
    print(f"=" * 70)
    print(f"Total Controls: {len(controls)}")
    print(f"Total Families: {len(families)}")
    print()
    
    for family_code in sorted(families.keys()):
        family_controls = families[family_code]
        print(f"{family_code} Family - {family_controls[0]['family']} ({len(family_controls)} controls)")
        for control in sorted(family_controls, key=lambda x: x['control_id']):
            print(f"  {control['control_id']}: {control['control_name']}")
        print()

def save_detailed_report(controls, output_file):
    """Save detailed report to a file."""
    families = group_by_family(controls)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("FedRAMP Moderate Baseline Revision 5 - Detailed Control Analysis\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Total Controls: {len(controls)}\n")
        f.write(f"Total Families: {len(families)}\n\n")
        
        for family_code in sorted(families.keys()):
            family_controls = families[family_code]
            f.write(f"\n{family_code} FAMILY - {family_controls[0]['family']}\n")
            f.write("-" * 50 + "\n")
            f.write(f"Controls in this family: {len(family_controls)}\n\n")
            
            for control in sorted(family_controls, key=lambda x: x['control_id']):
                f.write(f"Control ID: {control['control_id']}\n")
                f.write(f"Name: {control['control_name']}\n")
                f.write(f"Description: {control['description'][:200]}...\n" if len(control['description']) > 200 else f"Description: {control['description']}\n")
                if control['fedramp_params']:
                    f.write(f"FedRAMP Parameters: {control['fedramp_params']}\n")
                if control['fedramp_guidance']:
                    f.write(f"FedRAMP Guidance: {control['fedramp_guidance']}\n")
                f.write("\n" + "-" * 40 + "\n\n")

if __name__ == "__main__":
    csv_file = "/Users/kmobl/prowler/fedramp_moderate_rev5.csv"
    output_file = "/Users/kmobl/prowler/fedramp_rev5_analysis.txt"
    
    print("Parsing FedRAMP Moderate Revision 5 CSV file...")
    controls = parse_fedramp_csv(csv_file)
    
    print_control_summary(controls)
    save_detailed_report(controls, output_file)
    
    print(f"\nDetailed report saved to: {output_file}")
    
    # Extract just the control IDs for easy reference
    control_ids = [control['control_id'] for control in controls]
    print(f"\nAll Control IDs with 'X' parameter:")
    print(", ".join(sorted(control_ids)))
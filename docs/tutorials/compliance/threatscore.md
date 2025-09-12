# Prowler ThreatScore Documentation

## Table of Contents
- [Introduction](#introduction)
- [How ThreatScore Works](#how-threatscore-works)
- [Mathematical Formula](#mathematical-formula)
- [Parameters Explained](#parameters-explained)
- [Security Pillars and Subpillars](#security-pillars-and-subpillars)
- [Scoring Examples](#scoring-examples)
- [Implementation Details](#implementation-details)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)

## Introduction

The **Prowler ThreatScore** is a comprehensive compliance scoring system that provides a unified metric for assessing your organization's security posture across compliance frameworks. It aggregates findings from individual security checks into a single, normalized score ranging from 0 to 100.

### Purpose
- **Unified View**: Get a single metric representing overall compliance health
- **Risk Prioritization**: Understand which areas pose the highest security risks
- **Progress Tracking**: Monitor improvements in compliance posture over time
- **Executive Reporting**: Provide clear, quantifiable security metrics to stakeholders

## How ThreatScore Works

The ThreatScore calculation considers four critical factors for each compliance requirement:

### 1. Pass Rate (`rate_i`)
The percentage of security checks that passed for a specific requirement:
```
Pass Rate = (Number of PASS findings) / (Total findings)
```

### 2. Total Findings (`total_i`)
The total number of checks performed (both PASS and FAIL) for a requirement. This represents the amount of evidence available - more findings provide greater confidence in the assessment.

### 3. Weight (`weight_i`)
A numerical value (1-1000) representing the business importance or criticality of the requirement within your organization's context.

### 4. Risk Level (`risk_i`)
A severity rating (1-5) indicating the potential impact of non-compliance with this requirement.

## Mathematical Formula

The ThreatScore uses a weighted average formula that accounts for all four factors:

```
ThreatScore = (Σ(rate_i × total_i × weight_i × risk_i) / Σ(total_i × weight_i × risk_i)) × 100
```

Where:

- `rate_i` = Pass rate for requirement i (0.0 to 1.0)
- `total_i` = Total number of findings for requirement i
- `weight_i` = Business importance weight (1 to 1000)
- `risk_i` = Risk severity level (1 to 5)

### Formula Properties
- **Normalization**: Always produces a score between 0 and 100
- **Evidence-weighted**: Requirements with more findings have proportionally greater influence
- **Risk-sensitive**: Higher risk requirements impact the score more significantly
- **Business-aligned**: Weight values allow customization based on organizational priorities

## Parameters Explained

### Weight Values (1-1000)

The weight parameter allows you to customize ThreatScore calculation based on your organization's priorities and regulatory requirements.

#### Weight Assignment Guidelines

| Weight Range | Priority Level | Use Cases |
|--------------|----------------|-----------|
| 1-100 | Low | Optional or nice-to-have controls |
| 101-300 | Medium | Standard security practices |
| 301-600 | High | Important security controls |
| 601-850 | Critical | Regulatory compliance requirements |
| 851-1000 | Maximum | Mission-critical security controls |

#### Weight Selection Strategy
1. **Regulatory Mapping**: Assign higher weights to controls required by your industry regulations
2. **Business Impact**: Consider the potential business impact of control failures
3. **Risk Tolerance**: Align weights with your organization's risk appetite
4. **Stakeholder Input**: Involve compliance and business teams in weight decisions

### Risk Levels (1-5)

Risk levels represent the potential security impact of non-compliance with a requirement.

| Risk Level | Severity | Impact Description |
|------------|----------|-------------------|
| 1 | Very Low | Minimal security impact, informational |
| 2 | Low | Limited exposure, low probability of exploitation |
| 3 | Medium | Moderate security risk, potential for limited damage |
| 4 | High | Significant security risk, high probability of impact |
| 5 | Critical | Severe security risk, immediate threat to organization |

#### Risk Level Assessment Criteria
- **Confidentiality Impact**: Data exposure potential
- **Integrity Impact**: Risk of unauthorized data modification
- **Availability Impact**: Service disruption potential
- **Compliance Impact**: Regulatory violation consequences
- **Exploitability**: Ease of exploitation by attackers

## Security Pillars and Subpillars

Prowler organizes security requirements into a hierarchical structure of pillars and subpillars, providing a comprehensive framework for security assessment and compliance evaluation.

### Security Pillars Overview

The ThreatScore calculation considers requirements organized within the following security pillars:

#### 1. IAM (Identity and Access Management)
**Purpose**: Controls who can access what resources and under what conditions
**Subpillars**:

- **Authentication**: Verifying user and system identities
- **Authorization**: Controlling access to resources based on authenticated identity
- **Privilege Escalation**: Preventing unauthorized elevation of permissions

#### 2. Attack Surface
**Purpose**: Minimizing exposure points that could be exploited by attackers
**Coverage**: External-facing services, APIs, network endpoints, and system interfaces

#### 3. Network
**Purpose**: Securing network infrastructure and communications
**Coverage**: Network segmentation, firewall rules, VPC configurations, and traffic controls

#### 4. Storage
**Purpose**: Protecting data storage systems and access controls
**Coverage**: Database security, file system permissions, backup security, and storage encryption

#### 5. Application
**Purpose**: Securing application-level controls and configurations
**Coverage**: Application security settings, code security, runtime protections

#### 6. Logging and Monitoring
**Purpose**: Ensuring comprehensive visibility and audit capabilities
**Subpillars**:

- **Logging**: Capturing security-relevant events and activities
- **Retention**: Maintaining logs for appropriate time periods
- **Monitoring**: Active surveillance and alerting on security events

#### 7. Encryption
**Purpose**: Protecting data confidentiality through cryptographic controls
**Subpillars**:

- **In-Transit**: Encrypting data during transmission
- **At-Rest**: Encrypting stored data

### Pillar Hierarchy and ThreatScore Impact

#### Hierarchy Structure
```
Security Framework
├── Pillar (e.g., IAM)
│   ├── Subpillar (e.g., Authentication)
│   │   ├── Requirement (e.g., MFA Enabled)
│   │   │   ├── Check 1: Admin accounts use MFA
│   │   │   ├── Check 2: Regular users use MFA
│   │   │   └── Check N: Service accounts use MFA
│   │   └── [Additional Requirements]
│   └── [Additional Subpillars]
└── [Additional Pillars]
```

#### Weight and Risk Assignment by Pillar

Different pillars typically receive different weight and risk assignments based on their security impact:

| Pillar | Typical Weight Range | Typical Risk Range | Rationale |
|--------|---------------------|-------------------|-----------|
| IAM | 800-1000 | 4-5 | Critical for access control, high impact if compromised |
| Encryption | 700-950 | 4-5 | Essential for data protection, regulatory compliance |
| Logging and Monitoring | 600-800 | 3-4 | Important for detection and compliance, moderate direct impact |
| Network | 500-800 | 3-4 | Important for perimeter defense, varies by environment |
| Storage | 600-900 | 4-5 | High impact for data exposure, varies by data sensitivity |
| Application | 400-700 | 2-4 | Varies significantly by application criticality |
| Attack Surface | 500-800 | 3-5 | Highly dependent on exposure and criticality |

### Pillar-Specific Scoring Considerations

#### High-Impact Pillars (IAM, Encryption)
- **Characteristics**: Direct impact on data protection and access control
- **ThreatScore Impact**: Failures in these pillars significantly lower overall score
- **Weight Strategy**: Assign maximum weights (850-1000) to critical requirements
- **Risk Strategy**: Most requirements rated 4-5 due to severe consequences

#### Medium-Impact Pillars (Network, Storage, Logging)
- **Characteristics**: Important for security posture but impact varies by context
- **ThreatScore Impact**: Moderate influence on overall score
- **Weight Strategy**: Use business-driven weights (500-800) based on specific needs
- **Risk Strategy**: Risk levels vary (3-4) based on data and system criticality

#### Variable-Impact Pillars (Application, Attack Surface)
- **Characteristics**: Impact highly dependent on specific application and environment
- **ThreatScore Impact**: Customizable based on business context
- **Weight Strategy**: Requires careful assessment of business criticality
- **Risk Strategy**: Wide risk range (2-5) based on exposure and sensitivity

### Cross-Pillar Dependencies

#### Authentication ↔ Authorization (IAM)
- Strong authentication enables effective authorization controls
- Weight both subpillars highly as they're interdependent

#### Logging ↔ Monitoring (Logging and Monitoring)
- Logging provides the data that monitoring systems analyze
- Balance weights to ensure both data collection and analysis are prioritized

#### In-Transit ↔ At-Rest (Encryption)
- Comprehensive data protection requires both encryption types
- Consider data flow patterns when assigning relative weights

### Pillar Coverage in ThreatScore

#### Complete Coverage Benefits
- **Comprehensive Assessment**: All security domains represented in score
- **Balanced View**: Prevents over-emphasis on single security aspect
- **Regulatory Alignment**: Covers requirements across major compliance frameworks

#### Partial Coverage Considerations
- **Focused Assessment**: Target specific security domains
- **Resource Optimization**: Concentrate efforts on high-priority areas
- **Gradual Implementation**: Phase in additional pillars over time

## Scoring Examples

### Example 1: Basic Two-Requirement Scenario

Consider a compliance framework with two requirements:

**Requirement 1: Encryption at Rest**

- Findings: 200 PASS, 500 FAIL (total = 700)
- Pass Rate: 200/700 = 0.286 (28.6%)
- Weight: 500 (High priority - data protection)
- Risk Level: 4 (High risk - data exposure)

**Requirement 2: Access Logging**

- Findings: 300 PASS, 100 FAIL (total = 400)
- Pass Rate: 300/400 = 0.75 (75%)
- Weight: 800 (Critical for audit compliance)
- Risk Level: 3 (Medium risk - audit trail)

**Calculation:**
```
Numerator = (0.286 × 700 × 500 × 4) + (0.75 × 400 × 800 × 3)
          = (400,400) + (720,000)
          = 1,120,400

Denominator = (700 × 500 × 4) + (400 × 800 × 3)
            = 1,400,000 + 960,000
            = 2,360,000

ThreatScore = (1,120,400 / 2,360,000) × 100 = 47.5%
```

### Example 2: Enterprise Scenario with Pillar Structure

This example demonstrates how pillar organization affects ThreatScore calculation:

| Pillar | Subpillar | Requirement | Pass | Fail | Total | Weight | Risk | Pass Rate |
|--------|-----------|-------------|------|------|-------|--------|------|-----------|
| Encryption | At-Rest | PHI Encryption | 450 | 50 | 500 | 950 | 5 | 90% |
| IAM | Authorization | Access Controls | 280 | 120 | 400 | 800 | 4 | 70% |
| Logging and Monitoring | Logging | Audit Logging | 350 | 50 | 400 | 700 | 3 | 87.5% |
| Storage | - | Backup Security | 200 | 100 | 300 | 600 | 3 | 66.7% |
| Network | - | Network Segmentation | 150 | 50 | 200 | 750 | 4 | 75% |

**Step-by-step Calculation:**

1. **Calculate weighted contributions for each requirement:**

   - Encryption: 0.90 × 500 × 950 × 5 = 2,137,500
   - Access Controls: 0.70 × 400 × 800 × 4 = 896,000
   - Audit Logging: 0.875 × 400 × 700 × 3 = 735,000
   - Backup Security: 0.667 × 300 × 600 × 3 = 360,060
   - Network Segmentation: 0.75 × 200 × 750 × 4 = 450,000

2. **Sum numerator:** 2,137,500 + 896,000 + 735,000 + 360,060 + 450,000 = **4,578,560**

3. **Calculate total weights:**

   - Encryption: 500 × 950 × 5 = 2,375,000
   - Access Controls: 400 × 800 × 4 = 1,280,000
   - Audit Logging: 400 × 700 × 3 = 840,000
   - Backup Security: 300 × 600 × 3 = 540,000
   - Network Segmentation: 200 × 750 × 4 = 600,000

4. **Sum denominator:** 2,375,000 + 1,280,000 + 840,000 + 540,000 + 600,000 = **5,635,000**

5. **Final ThreatScore:** (4,578,560 / 5,635,000) × 100 = **81.2%**

**Pillar-Level Analysis:**
- **Encryption pillar**: Highest contribution due to maximum weight (950) and risk (5)
- **IAM pillar**: Significant impact despite lower pass rate (70%) due to high weight (800)
- **Logging pillar**: Moderate contribution with good performance (87.5%)
- **Network pillar**: Strong performance (75%) with high weight (750) balances the score
- **Storage pillar**: Lowest performance (66.7%) but limited impact due to moderate weight (600)

### Example 3: Multi-Pillar Comprehensive Scenario

**Financial Services Organization - Multi-Framework Compliance**

| Pillar | Subpillar | Requirement | Pass | Fail | Weight | Risk | Pass Rate |
|--------|-----------|-------------|------|------|--------|------|-----------|
| IAM | Authentication | MFA Implementation | 180 | 20 | 900 | 5 | 90% |
| IAM | Authorization | Least Privilege Access | 150 | 50 | 850 | 4 | 75% |
| IAM | Privilege Escalation | Admin Account Controls | 95 | 5 | 950 | 5 | 95% |
| Encryption | At-Rest | Database Encryption | 300 | 20 | 900 | 5 | 93.8% |
| Encryption | In-Transit | API/Web Encryption | 250 | 10 | 800 | 4 | 96.2% |
| Network | - | Firewall Configuration | 400 | 100 | 600 | 3 | 80% |
| Attack Surface | - | Public Endpoint Security | 80 | 20 | 700 | 4 | 80% |
| Logging and Monitoring | Logging | Transaction Logging | 500 | 50 | 750 | 3 | 90.9% |
| Logging and Monitoring | Monitoring | Real-time Alerts | 200 | 50 | 700 | 4 | 80% |
| Storage | - | Data Classification | 300 | 100 | 650 | 3 | 75% |
| Application | - | Input Validation | 150 | 50 | 500 | 3 | 75% |

**Pillar Performance Summary:**
- **IAM Pillar Average**: ~87% (weighted by findings)
- **Encryption Pillar Average**: ~94% (weighted by findings)
- **Network Pillar**: 80%
- **Attack Surface Pillar**: 80%
- **Logging and Monitoring Average**: ~87% (weighted by findings)
- **Storage Pillar**: 75%
- **Application Pillar**: 75%

**Overall ThreatScore**: ~85.3%

This comprehensive example demonstrates how:
- High-performing, high-weight pillars (Encryption, IAM) significantly boost the score
- Multiple requirements within pillars provide detailed granular assessment
- Cross-pillar balance prevents single points of failure in security posture

### Example 4: Impact of Parameter Changes

Using the scenario, let's see how parameter changes affect the score:

#### Scenario A: Increase Encryption Risk Level
Change Encryption risk from 5 to 3:

- **New ThreatScore: 77.8%** (decrease of 3.4 points)
- **Impact**: Lower risk weighting reduces the influence of high-performing critical controls

#### Scenario B: Improve Access Controls Pass Rate
Change Access Controls from 70% to 90% pass rate:

- **New ThreatScore: 85.1%** (increase of 3.9 points)
- **Impact**: Improving performance on high-weight requirements has significant score impact

#### Scenario C: Add New Low-Weight Requirement
Add "Documentation Completeness" (50 PASS, 10 FAIL, weight=100, risk=1):

- **New ThreatScore: 81.3%** (minimal change of 0.1 points)
- **Impact**: Low-weight requirements have minimal impact on overall score

## Implementation Details

### Edge Cases and Special Conditions

#### Zero Findings Scenario
When a requirement has `total_i = 0` (no findings):

- **Behavior**: Requirement is completely excluded from calculation
- **Rationale**: No evidence means no contribution to confidence in the score
- **Impact**: Other requirements receive proportionally more influence

#### Perfect Score Scenario
When all requirements have 100% pass rate:

- **Result**: ThreatScore = 100%
- **Interpretation**: All implemented security checks are passing

#### Zero Pass Rate Scenario
When all requirements have 0% pass rate:

- **Result**: ThreatScore = 0%
- **Interpretation**: Critical security failures across all requirements

#### Single Requirement Framework
For frameworks with only one requirement:

- **Formula simplification**: ThreatScore = pass_rate × 100
- **Impact**: Weight and risk values become irrelevant for score calculation

### Performance Considerations

#### Computational Complexity
- **Time Complexity**: O(n) where n = number of requirements
- **Space Complexity**: O(1) - constant space for accumulation
- **Scalability**: Efficiently handles frameworks with thousands of requirements

#### Calculation Precision
- **Floating Point**: Use double precision for intermediate calculations
- **Rounding**: Final score rounded to 1 decimal place for display
- **Overflow Protection**: Validate that weight × risk × total values don't exceed system limits

### Data Requirements

#### Minimum Data Set
For each requirement, the following data must be available:
- **pass_count**: Number of PASS findings (integer ≥ 0)
- **fail_count**: Number of FAIL findings (integer ≥ 0)
- **weight**: Business importance (integer 1-1000)
- **risk**: Risk level (integer 1-5)

#### Data Validation Rules
```
total_i = pass_i + fail_i
rate_i = pass_i / total_i (when total_i > 0)
1 ≤ weight_i ≤ 1000
1 ≤ risk_i ≤ 5
```

#### Handling Invalid Data
- **Negative values**: Treat as 0 and log warning
- **Out-of-range weights/risk**: Clamp to valid range and log warning
- **Missing data**: Exclude requirement from calculation and log warning

## Best Practices

### Score Interpretation Guidelines

| ThreatScore | Interpretation | Recommended Actions |
|------------------|----------------|-------------------|
| 90-100% | Excellent | Maintain current controls, focus on continuous improvement |
| 80-89% | Good | Address remaining gaps, prepare for compliance audits |
| 70-79% | Acceptable | Prioritize high-risk failures, develop improvement plan |
| 60-69% | Needs Improvement | Immediate attention required, may not pass compliance audit |
| Below 60% | Critical | Emergency response needed, potential regulatory issues |

### Monitoring and Trending

1. **Establish Baseline**
   - Record initial ThreatScore after implementing measurement
   - Set realistic improvement targets based on organizational capacity
   - Track score changes over time to identify trends

2. **Regular Reporting**
   - Generate monthly ThreatScore reports for stakeholders
   - Highlight significant score changes and their causes
   - Include requirement-level breakdowns for detailed analysis

3. **Continuous Improvement**
   - Use score trends to identify systematic issues
   - Correlate score changes with security incidents or changes
   - Adjust weights and risk levels based on lessons learned

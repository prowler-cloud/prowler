# Prowler ThreatScore Documentation

## Table of Contents
- [Introduction](#introduction)
- [How ThreatScore Works](#how-threatscore-works)
- [Mathematical Formula](#mathematical-formula)
- [Parameters Explained](#parameters-explained)
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

| Weight Range | Priority Level | Use Cases | Examples |
|--------------|----------------|-----------|----------|
| 1-100 | Low | Optional or nice-to-have controls | Documentation standards, cosmetic configurations |
| 101-300 | Medium | Standard security practices | Regular backup schedules, basic access controls |
| 301-600 | High | Important security controls | Encryption requirements, network segmentation |
| 601-850 | Critical | Regulatory compliance requirements | PCI DSS payment data protection, HIPAA PHI controls |
| 851-1000 | Maximum | Mission-critical security controls | Root access controls, data exfiltration prevention |

#### Weight Selection Strategy
1. **Regulatory Mapping**: Assign higher weights to controls required by your industry regulations
2. **Business Impact**: Consider the potential business impact of control failures
3. **Risk Tolerance**: Align weights with your organization's risk appetite
4. **Stakeholder Input**: Involve compliance and business teams in weight decisions

### Risk Levels (1-5)

Risk levels represent the potential security impact of non-compliance with a requirement.

| Risk Level | Severity | Impact Description | Examples |
|------------|----------|-------------------|----------|
| 1 | Very Low | Minimal security impact, informational | Log retention policies, documentation completeness |
| 2 | Low | Limited exposure, low probability of exploitation | Non-critical service configurations, minor access issues |
| 3 | Medium | Moderate security risk, potential for limited damage | Unencrypted internal communications, weak password policies |
| 4 | High | Significant security risk, high probability of impact | Exposed databases, missing critical patches, weak authentication |
| 5 | Critical | Severe security risk, immediate threat to organization | Public access to sensitive data, no encryption of PII, admin access without MFA |

#### Risk Level Assessment Criteria
- **Confidentiality Impact**: Data exposure potential
- **Integrity Impact**: Risk of unauthorized data modification
- **Availability Impact**: Service disruption potential
- **Compliance Impact**: Regulatory violation consequences
- **Exploitability**: Ease of exploitation by attackers

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

### Example 2: Enterprise Scenario

**Healthcare Organization - HIPAA Compliance Framework**

| Requirement | Pass | Fail | Total | Weight | Risk | Pass Rate |
|-------------|------|------|-------|--------|------|-----------|
| PHI Encryption | 450 | 50 | 500 | 950 | 5 | 90% |
| Access Controls | 280 | 120 | 400 | 800 | 4 | 70% |
| Audit Logging | 350 | 50 | 400 | 700 | 3 | 87.5% |
| Backup Security | 200 | 100 | 300 | 600 | 3 | 66.7% |
| Network Segmentation | 150 | 50 | 200 | 750 | 4 | 75% |

**Step-by-step Calculation:**

1. **Calculate weighted contributions for each requirement:**
   - PHI Encryption: 0.90 × 500 × 950 × 5 = 2,137,500
   - Access Controls: 0.70 × 400 × 800 × 4 = 896,000
   - Audit Logging: 0.875 × 400 × 700 × 3 = 735,000
   - Backup Security: 0.667 × 300 × 600 × 3 = 360,060
   - Network Segmentation: 0.75 × 200 × 750 × 4 = 450,000

2. **Sum numerator:** 2,137,500 + 896,000 + 735,000 + 360,060 + 450,000 = **4,578,560**

3. **Calculate total weights:**
   - PHI Encryption: 500 × 950 × 5 = 2,375,000
   - Access Controls: 400 × 800 × 4 = 1,280,000
   - Audit Logging: 400 × 700 × 3 = 840,000
   - Backup Security: 300 × 600 × 3 = 540,000
   - Network Segmentation: 200 × 750 × 4 = 600,000

4. **Sum denominator:** 2,375,000 + 1,280,000 + 840,000 + 540,000 + 600,000 = **5,635,000**

5. **Final ThreatScore:** (4,578,560 / 5,635,000) × 100 = **81.2%**

### Example 3: Impact of Parameter Changes

Using the same healthcare scenario, let's see how parameter changes affect the score:

#### Scenario A: Increase PHI Encryption Risk Level
Change PHI Encryption risk from 5 to 3:
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

### Weight Assignment Best Practices

1. **Start with Regulatory Requirements**
   - Map compliance requirements to business weights
   - Assign highest weights (800-1000) to mandatory controls
   - Use medium weights (300-600) for recommended practices

2. **Consider Business Context**
   - Financial services: Prioritize data protection and fraud prevention
   - Healthcare: Emphasize PHI protection and access controls
   - Manufacturing: Focus on operational security and IP protection

3. **Regular Weight Reviews**
   - Review weights quarterly or after major business changes
   - Involve stakeholders from compliance, risk, and business units
   - Document weight assignment rationale for audit purposes

4. **Avoid Weight Inflation**
   - Don't assign maximum weights to too many requirements
   - Maintain relative differences between requirement priorities
   - Use full weight range to preserve score sensitivity

### Risk Level Best Practices

1. **Consistent Risk Assessment**
   - Use standardized risk assessment methodology (e.g., NIST, ISO 27001)
   - Consider both likelihood and impact in risk level assignment
   - Document risk level rationale for transparency

2. **Regular Risk Updates**
   - Reassess risk levels when threat landscape changes
   - Update risk levels after security incidents or near-misses
   - Consider seasonal or contextual risk factors

3. **Cross-Framework Consistency**
   - Maintain consistent risk levels across different compliance frameworks
   - Align risk levels with overall enterprise risk management
   - Coordinate with security and risk management teams

### Score Interpretation Guidelines

| ThreatScore Range | Interpretation | Recommended Actions |
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

## Troubleshooting

### Common Issues and Solutions

#### Issue: ThreatScore Appears Too High/Low
**Symptoms:**
- Score doesn't align with perceived security posture
- Stakeholders question score validity
- Score changes unexpectedly

**Possible Causes & Solutions:**
1. **Incorrect Weight Assignment**
   - *Problem*: Critical requirements have low weights, trivial ones have high weights
   - *Solution*: Review and realign weights with business priorities and regulatory requirements

2. **Inappropriate Risk Levels**
   - *Problem*: Risk levels don't reflect actual security impact
   - *Solution*: Reassess risk levels using standardized methodology (NIST, ISO 27001)

3. **Data Quality Issues**
   - *Problem*: Findings data contains errors or inconsistencies
   - *Solution*: Validate source data, implement data quality checks

#### Issue: Score Doesn't Change Despite Remediation
**Symptoms:**
- Security improvements don't reflect in ThreatScore
- Score remains static over time
- Fixed issues don't show impact

**Possible Causes & Solutions:**
1. **Low Weight/Risk Requirements Fixed**
   - *Problem*: Improvements made to low-impact requirements
   - *Solution*: Focus remediation efforts on high-weight, high-risk requirements

2. **Insufficient Findings Volume**
   - *Problem*: Fixed requirements have few total findings
   - *Solution*: Prioritize requirements with higher finding counts for maximum score impact

3. **Data Refresh Issues**
   - *Problem*: Calculation uses stale data
   - *Solution*: Verify data refresh procedures and timing

#### Issue: Score Volatility
**Symptoms:**
- Score fluctuates significantly between measurements
- Inconsistent results from similar configurations
- Unexpected score drops/increases

**Possible Causes & Solutions:**
1. **Dynamic Finding Counts**
   - *Problem*: Finding counts change due to environment changes
   - *Solution*: Establish baseline measurements, account for legitimate environment changes

2. **Inconsistent Weight/Risk Assignment**
   - *Problem*: Parameters changed between calculations
   - *Solution*: Implement version control for weight and risk parameters

3. **Calculation Errors**
   - *Problem*: Implementation bugs or precision issues
   - *Solution*: Validate calculation logic, use reference implementation for testing

### Debugging Steps

#### Step 1: Validate Input Data
```bash
# Check for data completeness
- Verify all requirements have pass/fail counts
- Confirm weight values are in range [1, 1000]
- Ensure risk values are in range [1, 5]
- Identify any missing or null values
```

#### Step 2: Manual Calculation Verification
```bash
# Spot-check calculation for a few requirements
- Calculate rate_i manually: pass_i / (pass_i + fail_i)
- Verify weight_i and risk_i values are correct
- Confirm numerator calculation: rate_i × total_i × weight_i × risk_i
- Confirm denominator calculation: total_i × weight_i × risk_i
```

#### Step 3: Parameter Impact Analysis
```bash
# Test parameter sensitivity
- Temporarily adjust one requirement's weight and observe score change
- Modify risk level for high-impact requirement and verify score response
- Add/remove requirements to test score stability
```

## FAQ

### General Questions

**Q: What's a good ThreatScore for my organization?**
A: Target scores depend on your industry and risk tolerance:
- **Financial Services/Healthcare**: Target 85-95% (high regulatory requirements)
- **Technology/SaaS**: Target 80-90% (balanced security and agility)
- **Manufacturing/Retail**: Target 75-85% (operational focus)
- **Startups/SMB**: Target 70-80% (resource constraints acceptable)

**Q: How often should I recalculate ThreatScore?**
A: Recommended frequencies:
- **Daily**: For continuous monitoring and rapid response
- **Weekly**: For regular security reviews and trend analysis
- **Monthly**: For stakeholder reporting and compliance tracking
- **Quarterly**: For strategic planning and parameter reviews

**Q: Can I compare ThreatScores across different compliance frameworks?**
A: Limited comparability due to:
- Different requirement sets and coverage areas
- Varying weight and risk assignments
- Framework-specific control definitions
- *Recommendation*: Use framework-specific scores for detailed analysis, aggregate for overall posture

### Technical Questions

**Q: What happens if a requirement has zero findings?**
A: Requirements with zero findings are excluded from calculation because:
- No evidence means no contribution to confidence
- Avoids artificially inflating or deflating scores
- Other requirements receive proportionally more weight

**Q: How do I handle requirements that aren't applicable to my environment?**
A: Options for non-applicable requirements:
1. **Exclude entirely**: Remove from framework definition
2. **Set weight to 1**: Minimize impact while maintaining framework completeness
3. **Mark as N/A**: Use separate tracking mechanism outside ThreatScore

**Q: Can ThreatScore be gamed by adjusting weights?**
A: Potential gaming scenarios and mitigations:
- **Weight inflation**: Assign maximum weights to well-performing requirements
  - *Mitigation*: Regular weight reviews with business justification
- **Risk deflation**: Artificially lower risk levels to reduce impact
  - *Mitigation*: Use standardized risk assessment methodology
- **Requirement selection**: Choose only easy-to-pass requirements
  - *Mitigation*: Use industry-standard compliance frameworks

### Implementation Questions

**Q: How do I determine appropriate weights for my requirements?**
A: Weight assignment process:
1. **Map to regulations**: Assign highest weights to mandatory compliance controls
2. **Assess business impact**: Consider financial, operational, and reputational risks
3. **Stakeholder input**: Involve compliance, risk, and business teams
4. **Industry benchmarking**: Reference industry-specific control frameworks
5. **Iterative refinement**: Adjust based on score behavior and feedback

**Q: What data sources can feed into ThreatScore calculation?**
A: Common data sources:
- **Security scanning tools**: Vulnerability scanners, configuration assessment tools
- **Compliance platforms**: GRC platforms, audit management systems
- **SIEM/Security tools**: Log analysis, security monitoring platforms
- **Manual assessments**: Audit findings, penetration test results
- **Cloud security tools**: CSPM, CWPP, cloud-native security platforms

**Q: How do I validate my ThreatScore implementation?**
A: Validation approaches:
1. **Reference calculations**: Manual calculation of sample scenarios
2. **Boundary testing**: Test with edge cases (all pass, all fail, single requirement)
3. **Parameter sensitivity**: Verify score changes with weight/risk modifications
4. **Data validation**: Implement input data quality checks
5. **Stakeholder review**: Confirm scores align with perceived security posture

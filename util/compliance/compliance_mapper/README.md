# 🛡️ Compliance Mapper CLI

An intelligent tool for mapping compliance frameworks with Prowler Hub security checks using AI analysis.

## Overview

The Compliance Mapper CLI is an interactive tool that automatically maps compliance framework requirements to relevant Prowler security checks. It uses AI analysis to intelligently select the most appropriate checks for each compliance requirement, providing justifications for the mappings.

## Features

- **Interactive CLI Interface**: Beautiful, user-friendly command-line interface using Rich
- **AI-Powered Analysis**: Uses OpenAI GPT-5 for intelligent check selection and mapping
- **Prowler Hub Integration**: Automatically fetches latest security checks from Prowler Hub API
- **GitHub Code Integration**: Retrieves actual check code from GitHub for deeper analysis
- **Flexible Field Selection**: Choose which compliance requirement fields to analyze
- **Concurrent Processing**: Fast processing using threading for API calls
- **Comprehensive Output**: Generates mapped compliance files with justifications

## Requirements

- Python 3.7+
- Internet connection (for Prowler Hub API and GitHub access)
- OpenAI API key (for AI analysis)

### Dependencies

The tool automatically installs required dependencies, but you can install them manually:

```bash
pip install rich requests
```

## Installation

1. Clone or download the `compliance_mapper.py` file
2. Make it executable:
   ```bash
   chmod +x compliance_mapper.py
   ```

## Usage

### Interactive Mode (Recommended)

Run the tool without arguments to enter interactive mode:

```bash
python compliance_mapper.py
```

### Command Line Arguments

```bash
python compliance_mapper.py [options]

Options:
  -f, --file    Path to compliance framework JSON file
  -o, --output  Output file path
  -h, --help    Show help message
```

## Workflow

The tool follows a 6-step interactive workflow:

### 1. Load Compliance File
- Provide path to your compliance framework JSON file
- The tool validates the file structure and displays framework information
- Suggested JSON structure:
  ```json
  {
    "Framework": "Framework Name",
    "Provider": "aws|azure|gcp",
    "Version": "1.0",
    "Requirements": [
      {
        "Id": "REQ-001",
        "Description": "Requirement description",
        "Attributes": [
          {
            "Section": "Control section",
            "SubSection": "Detailed description"
          }
        ]
      }
    ]
  }
  ```

### 2. Field Selection
- The tool analyzes your compliance file structure
- Select which fields to use for AI analysis (e.g., Description, Attributes.Section)
- Fields with substantial text content are recommended for better AI analysis

### 3. Load Prowler Checks
- Automatically fetches all security checks for your provider from Prowler Hub
- Displays summary of loaded checks (count, services, severity levels)

### 4. Add Check Code
- Retrieves actual Python code for each check from GitHub
- Uses concurrent processing for faster execution
- Code is used by AI for deeper technical analysis

### 5. Process Requirements
- **OpenAI API Setup**: Enter your OpenAI API key or set `OPENAI_API_KEY` environment variable
- **Additional Field Option**: Choose whether to include AI justifications in output
- **AI Analysis**: Each requirement is analyzed against all available checks
- Progress tracking with real-time updates

### 6. Generate Output
- Creates new JSON file with mapped checks
- Updates `Checks` field with selected check IDs
- Optionally includes `Attributes.Additional` field with AI justifications

## OpenAI API Key

The tool requires an OpenAI API key for AI analysis:

1. **Environment Variable** (Recommended):
   ```bash
   export OPENAI_API_KEY="your-api-key-here"
   ```

2. **Interactive Input**: Enter when prompted during execution

3. **Get API Key**: Visit [OpenAI Platform](https://platform.openai.com/api-keys)

## Input File Format

Your compliance framework JSON must include:

- `Framework`: Name of the compliance framework
- `Provider`: Cloud provider (aws, azure, gcp)
- `Requirements`: Array of compliance requirements

Each requirement should have:
- `Id`: Unique identifier
- Text fields for analysis (Description, Attributes.Section, etc.)
- `Attributes`: Array of attribute objects (optional)

## Output Format

The tool generates a new JSON file with:
- Original compliance framework structure preserved
- `Checks`: Array of mapped Prowler check IDs for each requirement
- `Attributes.Additional`: AI justification for mappings (if enabled)

Example output requirement:
```json
{
  "Id": "REQ-001",
  "Description": "Ensure encryption at rest",
  "Checks": ["s3_bucket_default_encryption", "rds_instance_storage_encrypted"],
  "Attributes": [
    {
      "Section": "Data Protection",
      "Additional": "Selected checks validate encryption controls: s3_bucket_default_encryption ensures S3 buckets have default encryption enabled, and rds_instance_storage_encrypted verifies RDS instances use encrypted storage."
    }
  ]
}
```

## Error Handling

The tool includes comprehensive error handling:
- **File Validation**: Checks JSON structure and required fields
- **API Connectivity**: Handles Prowler Hub and OpenAI API issues
- **Rate Limiting**: Automatically handles OpenAI rate limits with delays
- **Network Issues**: Retry logic for temporary connection problems
- **Invalid Responses**: Graceful handling of malformed AI responses

## Performance

- **Concurrent Processing**: Uses ThreadPoolExecutor for parallel API calls
- **Progress Tracking**: Real-time progress indicators
- **Rate Limiting**: 1-second delay between AI requests to respect API limits
- **Caching**: Efficient data structures to minimize redundant processing

## Troubleshooting

### Common Issues

1. **"No suitable fields found"**
   - Ensure your requirements have text fields with substantial content
   - Check that field values are longer than 10 characters

2. **"Failed to connect to Prowler Hub"**
   - Verify internet connection
   - Check if Prowler Hub API is accessible
   - Ensure provider name is valid (aws, azure, gcp)

3. **"Authentication failed"**
   - Verify OpenAI API key is correct
   - Check API key has sufficient credits
   - Ensure key has access to required models

4. **"API request failed"**
   - Check internet connectivity
   - Verify API endpoints are accessible
   - Review rate limiting and try again later

### Debug Information

The tool provides detailed error messages and progress information. For additional debugging:
- Check file paths are correct and accessible
- Verify JSON file structure matches requirements
- Ensure all required fields are present in compliance data

## Example Usage

```bash
# Interactive mode
python compliance_mapper.py

# Load specific file
python compliance_mapper.py -f ./frameworks/nist_csf.json

# Specify output location
python compliance_mapper.py -f ./frameworks/nist_csf.json -o ./output/mapped_nist.json
```

## Contributing

This tool is part of the Prowler project. For issues, improvements, or contributions, please refer to the main Prowler repository.

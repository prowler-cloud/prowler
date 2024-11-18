
# Prowler Check Kreator

???+ note
    Currently, this tool is only available for creating checks for the AWS provider.

**Prowler Check Kreator** is a utility designed to streamline the creation of new checks for Prowler. This tool generates all necessary files required to add a new check to the Prowler repository. Specifically, it creates:

- A dedicated folder for the check.
- The main check script.
- A metadata file with essential details.
- A folder and file structure for testing the check.

## Usage

To use the tool, execute the main script with the following command:

```bash
python util/prowler_check_kreator/prowler_check_kreator.py <prowler_provider> <check_name>
```
Parameters:

- `<prowler_provider>`: Currently only AWS is supported.
- `<check_name>`: The name you wish to assign to the new check.

## AI integration

This tool optionally integrates AI to assist in generating the check code and metadata file content. When AI assistance is chosen, the tool uses [Gemini](https://gemini.google.com/) to produce preliminary code and metadata.

???+ note
    For this feature to work, you must have the library `google-generativeai` installed in your Python environment.

???+ warning
    AI-generated code and metadata might contain errors or require adjustments to align with specific Prowler requirements. Carefully review all AI-generated content before committing.

To enable AI assistance, simply confirm when prompted by the tool. Additionally, ensure that the `GEMINI_API_KEY` environment variable is set with a valid Gemini API key. For instructions on obtaining your API key, refer to the [Gemini documentation](https://ai.google.dev/gemini-api/docs/api-key).

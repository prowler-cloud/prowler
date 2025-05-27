from prowler.providers.iac.iac_provider import IACProvider

provider = IACProvider(scan_path=globals().get("args", None).scan_path)

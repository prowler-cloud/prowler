def init_parser(self):
    """Init the LLM Provider CLI parser"""
    llm_parser = self.subparsers.add_parser(
        "llm", parents=[self.common_providers_parser], help="LLM Provider"
    )

    llm_parser.add_argument(
        "--model-type",
        dest="model_type",
        default="openai",
        help="Type of LLM model to use. Default: openai",
    )

    llm_parser.add_argument(
        "--model-name",
        dest="model_name",
        default="gpt-4o",
        help="Name of the LLM model to use. Default: gpt-4o",
    )

    llm_parser.add_argument(
        "--probes",
        dest="probes",
        nargs="+",
        default=[
            "promptinject.HijackLongPrompt",
            "promptinject.HijackKillHumans",
            "latentinjection.LatentJailbreak",
            "latentinjection.LatentInjectionReport",
            "encoding.InjectBase64",
            "encoding.InjectHex",
            "encoding.InjectROT13",
            "exploitation.JinjaTemplatePythonInjection",
            "xss.MarkdownImageExfil",
            "xss.MdExfil20230929",
            "ansiescape.AnsiEscaped",
            "suffix.GCGCached",
        ],
        help="Comma-separated list of Garak security probes to use. Default: Baseline probes",
    )

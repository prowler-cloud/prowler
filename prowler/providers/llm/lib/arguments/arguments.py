def init_parser(self):
    """Init the LLM Provider CLI parser"""
    llm_parser = self.subparsers.add_parser(
        "llm", parents=[self.common_providers_parser], help="LLM Provider"
    )

    llm_parser.add_argument(
        "--max-concurrency",
        dest="max_concurrency",
        type=int,
        default=10,
        help="Maximum number of concurrent requests. Default: 10",
    )

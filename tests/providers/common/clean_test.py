import importlib
import logging
import tempfile
from argparse import Namespace
from os import path

from mock import patch

from prowler.providers.common.clean import clean_provider_local_output_directories


class Test_Common_Clean:
    def set_provider_input_args(self, provider):
        set_args_function = f"set_{provider}_input_args"
        args = getattr(
            getattr(importlib.import_module(__name__), __class__.__name__),
            set_args_function,
        )(self)
        return args

    def set_aws_input_args(self):
        args = Namespace()
        args.provider = "aws"
        args.output_bucket = "test-bucket"
        args.output_bucket_no_assume = None
        return args

    def set_azure_input_args(self):
        args = Namespace()
        args.provider = "azure"
        return args

    def test_clean_provider_local_output_directories_non_initialized(self, caplog):
        provider = "azure"
        input_args = self.set_provider_input_args(provider)
        caplog.set_level(logging.INFO)
        clean_provider_local_output_directories(input_args)
        assert (
            f"Cleaning local output directories not initialized for provider {provider}:"
            in caplog.text
        )

    def test_clean_aws_local_output_directories_non_default_dir_output_bucket(self):
        provider = "aws"
        input_args = self.set_provider_input_args(provider)
        with tempfile.TemporaryDirectory() as temp_dir:
            input_args.output_directory = temp_dir
            clean_provider_local_output_directories(input_args)
            assert not path.exists(input_args.output_directory)

    def test_clean_aws_local_output_directories_non_default_dir_output_bucket_no_assume(
        self,
    ):
        provider = "aws"
        input_args = self.set_provider_input_args(provider)
        input_args.output_bucket = None
        input_args.output_bucket_no_assume = "test"
        with tempfile.TemporaryDirectory() as temp_dir:
            input_args.output_directory = temp_dir
            clean_provider_local_output_directories(input_args)
            assert not path.exists(input_args.output_directory)

    def test_clean_aws_local_output_directories_default_dir_output_bucket(self):
        provider = "aws"
        input_args = self.set_provider_input_args(provider)
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch(
                "prowler.providers.common.clean.default_output_directory", new=temp_dir
            ):
                input_args.output_directory = temp_dir
                clean_provider_local_output_directories(input_args)
                assert path.exists(input_args.output_directory)

    def test_clean_aws_local_output_directories_default_dir_output_bucket_no_assume(
        self,
    ):
        provider = "aws"
        input_args = self.set_provider_input_args(provider)
        input_args.output_bucket_no_assume = "test"
        input_args.ouput_bucket = None
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch(
                "prowler.providers.common.clean.default_output_directory", new=temp_dir
            ):
                input_args.output_directory = temp_dir
                clean_provider_local_output_directories(input_args)
                assert path.exists(input_args.output_directory)

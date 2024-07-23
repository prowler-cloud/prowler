from os import path
from tempfile import NamedTemporaryFile

from boto3 import Session

from prowler.lib.logger import logger
from prowler.lib.outputs.output import Output


class S3:
    """
    A class representing an S3 bucket.

    Attributes:
    - _session: An instance of the `Session` class representing the AWS session.
    - _bucket_name: A string representing the name of the S3 bucket.
    - _output_directory: A string representing the output directory path.

    Methods:
    - __init__: Initializes a new instance of the `S3` class.
    - get_object_path: Returns the object path within the S3 bucket based on the provided output directory.
    - generate_subfolder_name_by_extension: Generates a subfolder name based on the provided file extension.
    - send_to_bucket: Sends the provided outputs to the S3 bucket.
    """

    _session: Session
    _bucket_name: str
    _output_directory: str

    def __init__(
        self, session: Session, bucket_name: str, output_directory: str
    ) -> None:
        """
        Initializes a new instance of the `S3` class.

        Parameters:
        - session: An instance of the `Session` class representing the AWS session.
        - bucket_name: A string representing the name of the S3 bucket.
        - output_directory: A string representing the output directory path.
        """
        self._session = session.client(__class__.__name__.lower())
        self._bucket_name = bucket_name
        self._output_directory = output_directory

    @staticmethod
    def get_object_path(output_directory: str) -> str:
        """
        Return the object path within the S3 bucket based on the provided output directory.
        If the output directory contains "prowler/", it is removed to ensure the correct path is returned.

        Parameters:
        - output_directory: A string representing the output directory path.

        Returns:
        - A string representing the object path within the S3 bucket.
        """
        bucket_remote_dir = output_directory
        if "prowler/" in bucket_remote_dir:  # Check if it is not a custom directory
            bucket_remote_dir = bucket_remote_dir.partition("prowler/")[-1]

        return bucket_remote_dir

    @staticmethod
    def generate_subfolder_name_by_extension(extension: str) -> str:
        """
        Generate a subfolder name based on the provided file extension.

        Parameters:
        - extension: A string representing the file extension.

        Returns:
        - A string representing the subfolder name based on the extension.
        """
        subfolder_name = ""
        if extension == ".ocsf.json":
            subfolder_name = "json-ocsf"
        elif extension == ".asff.json":
            subfolder_name = "json-asff"
        else:
            subfolder_name = extension.lstrip(".")
        return subfolder_name

    # TODO: Review the logic behind in Microsoft Windows
    def send_to_bucket(
        self, outputs: dict[str, list[Output]]
    ) -> dict[str, dict[str, list[str]]]:
        """
        Send the provided outputs to the S3 bucket.

        Parameters:
        - outputs: A dictionary where keys are strings and values are lists of Output objects.

        Returns:
        - A dictionary containing two keys: "success" and "failure", each holding a dictionary where keys are strings and values are lists of strings representing the uploaded object names or tuples of object names and errors respectively.
        """
        try:
            uploaded_objects = {"success": {}, "failure": {}}
            # Keys are regular and/or compliance
            for key, output_list in outputs.items():
                for output in output_list:
                    try:
                        # Object is not written to file so we need to temporarily write it
                        if not hasattr(output, "file_descriptor"):
                            output.file_descriptor = NamedTemporaryFile(mode="a")

                        bucket_directory = self.get_object_path(self._output_directory)
                        basename = path.basename(output.file_descriptor.name)

                        if key == "compliance":
                            object_name = f"{bucket_directory}/{key}/{basename}"
                        else:
                            object_name = f"{bucket_directory}/{self.generate_subfolder_name_by_extension(output.file_extension)}/{basename}"
                        logger.info(
                            f"Sending output file {output.file_descriptor.name} to S3 bucket {self._bucket_name}"
                        )

                        # TODO: This will need further optimization if some processes are calling this since the files are written
                        # into the local filesystem because S3 upload file is the recommended way.
                        # https://aws.amazon.com/blogs/developer/uploading-files-to-amazon-s3/
                        self._session.upload_file(
                            output.file_descriptor.name, self._bucket_name, object_name
                        )

                        if output.file_extension in uploaded_objects["success"]:
                            uploaded_objects["success"][output.file_extension].append(
                                object_name
                            )
                        else:
                            uploaded_objects["success"] = {
                                output.file_extension: [object_name]
                            }
                    except Exception as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )
                        if output.file_extension in uploaded_objects["failure"]:
                            uploaded_objects["failure"][output.file_extension].append(
                                (object_name, error)
                            )
                        else:
                            uploaded_objects["failure"] = {
                                output.file_extension: [(object_name, error)]
                            }

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
        return uploaded_objects

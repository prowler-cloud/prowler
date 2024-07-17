from os import path

from boto3 import Session

from prowler.lib.logger import logger
from prowler.lib.outputs.output import Output


class S3:
    _session: Session
    _bucket_name: str
    _output_directory: str

    def __init__(
        self, session: Session, bucket_name: str, output_directory: str
    ) -> None:
        self._session = session.client(__class__.__name__.lower())
        self._bucket_name = bucket_name
        self._output_directory = output_directory

    @staticmethod
    def get_object_path(output_directory: str) -> str:
        bucket_remote_dir = output_directory
        if "prowler/" in bucket_remote_dir:  # Check if it is not a custom directory
            bucket_remote_dir = bucket_remote_dir.partition("prowler/")[-1]

        return bucket_remote_dir

    def send_to_bucket(self, outputs: dict[str, list[Output]]) -> dict[str, str]:
        """ "
        Uploads output files to an S3 bucket based on the provided outputs dictionary. Returns the count of successfully uploaded files.

        Parameters:
        - outputs: A dictionary containing lists of Output objects categorized as 'regular' and 'compliance'.

        Returns:
        - An integer representing the count of successfully uploaded files.
        """
        try:
            uploaded_objects = {"success": [], "failure": []}
            for output in outputs.get("regular", []):
                try:
                    # TODO(PRWLR-4186): this does not support sending an output that has not been written to file previously.
                    # Something will need to be changed using TemporaryFile
                    # Object is not written to file so we need to temporarily write it
                    # if not hasattr(output, "file_descriptor"):
                    #     output.file_descriptor = TemporaryFile(mode="a")

                    # FIXME: windows?
                    bucket_directory = self.get_object_path(self._output_directory)
                    # TODO(PRWLR-4186): Get it from the output
                    _, extension = path.splitext(output.file_descriptor.name)
                    object_name = f"{bucket_directory}/{extension.lstrip(".")}/{path.basename(output.file_descriptor.name)}"
                    logger.info(
                        f"Sending output file {output.file_descriptor.name} to S3 bucket {self._bucket_name}"
                    )

                    # This will need further optimization if some processes are calling this since the files are written
                    # into the local filesystem because S3 upload file is the recommended way.
                    # https://aws.amazon.com/blogs/developer/uploading-files-to-amazon-s3/
                    # TODO: review the above
                    self._session.upload_file(
                        output.file_descriptor.name, self._bucket_name, object_name
                    )

                    uploaded_objects["success"].append(object_name)
                except Exception as error:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                    )
                    uploaded_objects["failure"].append(object_name)
            for output in outputs.get("compliance", []):
                try:
                    # TODO: what if there is no file descriptor? maybe use put_object
                    # FIXME: windows?
                    bucket_directory = self.get_object_path(self._output_directory)
                    object_name = f"{bucket_directory}/compliance/{path.basename(output.file_descriptor.name)}"
                    logger.info(
                        f"Sending output file {output.file_descriptor.name} to S3 bucket {self._bucket_name}"
                    )
                    self._session.upload_file(
                        output.file_descriptor.name, self._bucket_name, object_name
                    )
                    uploaded_objects["success"].append(object_name)
                except Exception as error:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                    )
                    uploaded_objects["failure"].append(object_name)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )

        return uploaded_objects

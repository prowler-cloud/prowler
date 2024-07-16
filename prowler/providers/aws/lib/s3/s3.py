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

    def send_to_bucket(self, outputs: list[Output]) -> int:
        try:
            success_count = 0
            for output in outputs:
                try:
                    # FIXME: compliance
                    # else:  # Compliance output mode
                    #     filename = f"{output_filename}_{output_mode}{csv_file_suffix}"
                    #     file_name = output_directory + "/compliance/" + filename
                    #     object_name = bucket_directory + "/compliance/" + filename

                    # TODO: what if there is no file descriptor? maybe use put_object
                    # FIXME: windows?
                    bucket_directory = self.get_object_path(self._output_directory)
                    _, extension = path.splitext(output.file_descriptor.name)
                    object_name = f"{bucket_directory}/{extension.lstrip(".")}/{path.basename(output.file_descriptor.name)}"
                    logger.info(
                        f"Sending output file {output.file_descriptor.name} to S3 bucket {self._bucket_name}"
                    )

                    self._session.upload_file(
                        output.file_descriptor.name, self._bucket_name, object_name
                    )
                    success_count += 1
                except Exception as error:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )

        return success_count

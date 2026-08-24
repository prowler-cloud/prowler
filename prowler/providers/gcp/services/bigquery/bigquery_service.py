import threading
from concurrent.futures import ThreadPoolExecutor

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.config import DEFAULT_RETRY_ATTEMPTS
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.lib.service.service import GCPService

# Both datasets.get and tables.get are one round trip per resource, and a
# production BigQuery estate can hold tens of thousands of tables. Bounded so a
# large estate cannot exhaust the BigQuery API quota.
MAX_WORKERS = 10


class BigQuery(GCPService):
    def __init__(self, provider: GcpProvider):
        super().__init__(__class__.__name__, provider, api_version="v2")

        self.datasets = []
        self.tables = []
        self._thread_local = threading.local()
        # One pool for the whole enumeration rather than one per project and
        # another for tables. Each pool spawns its own threads, and the http
        # clients below are thread-local, so a pool per project would let the
        # client count scale with the project count instead of staying at
        # MAX_WORKERS.
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            self._get_datasets(executor)
            self._get_tables(executor)

    def _get_thread_http(self):
        """One AuthorizedHttp per worker thread.

        googleapiclient's http object is not thread safe, so a threaded call
        cannot share the client's own. Building one per *thread* rather than per
        *request* keeps the count at MAX_WORKERS instead of one per resource,
        which matters when the estate has thousands of tables.

        Returns:
            An ``AuthorizedHttp`` belonging to the calling thread, created on
            first use and cached on thread-local storage thereafter.
        """
        http = getattr(self._thread_local, "http", None)
        if http is None:
            http = self.__get_AuthorizedHttp_client__()
            self._thread_local.http = http
        return http

    def _get_datasets(self, executor):
        """Populate ``self.datasets`` for every audited project.

        Datasets are listed serially, then described concurrently because
        ``datasets.get`` is one round trip per dataset. Results are appended in
        listing order, not completion order.

        Args:
            executor: The shared pool for the enumeration's lifetime. Shared so
                the worker count, and therefore the thread-local http clients,
                stay bounded across every project.

        Returns:
            None. Appends to ``self.datasets`` as a side effect.
        """
        for project_id in self.project_ids:
            try:
                # Listing is a handful of paged calls; the per-dataset get below
                # is what dominates, so only that is parallelised.
                dataset_refs = []
                request = self.client.datasets().list(projectId=project_id)
                while request is not None:
                    response = request.execute(num_retries=DEFAULT_RETRY_ATTEMPTS)
                    dataset_refs.extend(response.get("datasets", []))
                    request = self.client.datasets().list_next(
                        previous_request=request, previous_response=response
                    )

                if not dataset_refs:
                    continue

                # executor.map preserves input order, so self.datasets is built
                # in listing order regardless of completion order.
                for dataset, dataset_info in zip(
                    dataset_refs,
                    executor.map(
                        lambda ref: self._describe_dataset(project_id, ref),
                        dataset_refs,
                    ),
                ):
                    if dataset_info is None:
                        continue
                    cmk_encryption = False
                    public = False
                    roles = dataset_info.get("access", "")
                    if "allAuthenticatedUsers" in str(roles) or "allUsers" in str(
                        roles
                    ):
                        public = True
                    if dataset_info.get("defaultEncryptionConfiguration"):
                        cmk_encryption = True
                    self.datasets.append(
                        Dataset(
                            name=dataset["datasetReference"]["datasetId"],
                            id=dataset["id"],
                            region=dataset["location"],
                            cmk_encryption=cmk_encryption,
                            public=public,
                            project_id=project_id,
                        )
                    )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _describe_dataset(self, project_id, dataset_ref):
        """Fetch one dataset's detail.

        Args:
            project_id: Project owning the dataset.
            dataset_ref: A ``datasets.list`` entry for the dataset to describe.

        Returns:
            The ``datasets.get`` response, or ``None`` if it could not be read,
            in which case the dataset is skipped rather than failing its
            siblings.
        """
        try:
            return (
                self.client.datasets()
                .get(
                    projectId=project_id,
                    datasetId=dataset_ref["datasetReference"]["datasetId"],
                )
                .execute(
                    http=self._get_thread_http(),
                    num_retries=DEFAULT_RETRY_ATTEMPTS,
                )
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None

    def _get_tables(self, executor):
        """Populate ``self.tables`` for every dataset already discovered.

        Table references are listed serially, then described concurrently
        across all datasets at once, because ``tables.get`` is one round trip
        per table and a production estate can hold tens of thousands. Results
        are appended in listing order.

        Args:
            executor: The shared pool for the enumeration's lifetime, the same
                one used for datasets.

        Returns:
            None. Appends to ``self.tables`` as a side effect.
        """
        # Collect every table reference first. Listing is fast even for large
        # estates; it is the per-table get that made this O(tables) in wall
        # clock, so the refs are gathered here and described concurrently below.
        table_refs = []
        for dataset in self.datasets:
            try:
                request = self.client.tables().list(
                    projectId=dataset.project_id, datasetId=dataset.name
                )
                while request is not None:
                    response = request.execute(num_retries=DEFAULT_RETRY_ATTEMPTS)
                    for table in response.get("tables", []):
                        table_refs.append((dataset, table))
                    request = self.client.tables().list_next(
                        previous_request=request, previous_response=response
                    )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        if not table_refs:
            return

        try:
            # Every dataset's tables go through the one shared pool, so the
            # concurrency ceiling is global rather than multiplied by the
            # dataset count. executor.map preserves input order, so self.tables
            # stays in listing order.
            described = executor.map(self._describe_table, table_refs)

            for (dataset, table), table_info in zip(table_refs, described):
                if table_info is None:
                    continue
                self.tables.append(
                    Table(
                        name=table["tableReference"]["tableId"],
                        id=table["id"],
                        region=dataset.region,
                        cmk_encryption=bool(table_info.get("encryptionConfiguration")),
                        project_id=dataset.project_id,
                    )
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_table(self, ref):
        """Fetch one table's detail.

        Args:
            ref: A ``(dataset, table_ref)`` pair, where ``table_ref`` is a
                ``tables.list`` entry belonging to ``dataset``.

        Returns:
            The ``tables.get`` response, or ``None`` if it could not be read,
            in which case the table is skipped rather than failing the rest of
            its dataset.
        """
        dataset, table = ref
        try:
            return (
                self.client.tables()
                .get(
                    projectId=dataset.project_id,
                    datasetId=dataset.name,
                    tableId=table["tableReference"]["tableId"],
                )
                .execute(
                    http=self._get_thread_http(),
                    num_retries=DEFAULT_RETRY_ATTEMPTS,
                )
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None


class Dataset(BaseModel):
    name: str
    id: str
    region: str
    cmk_encryption: bool
    public: bool
    project_id: str


class Table(BaseModel):
    name: str
    id: str
    region: str
    cmk_encryption: bool
    project_id: str

Scan report generation no longer holds a database transaction open while it renders and uploads files, which could block schema changes for the length of the report

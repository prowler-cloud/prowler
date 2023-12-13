from csv import DictWriter


def write_csv(file_descriptor, headers, row):
    csv_writer = DictWriter(
        file_descriptor,
        fieldnames=headers,
        delimiter=";",
    )
    csv_writer.writerow(row.__dict__)

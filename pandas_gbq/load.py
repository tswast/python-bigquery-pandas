# Copyright (c) 2017 pandas-gbq Authors All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

"""Helper methods for loading data into BigQuery"""

import io

from google.cloud import bigquery

from pandas_gbq.features import FEATURES
import pandas_gbq.schema


def encode_chunk(dataframe):
    """Return a file-like object of CSV-encoded rows.

    Args:
      dataframe (pandas.DataFrame): A chunk of a dataframe to encode
    """
    csv_buffer = io.StringIO()
    dataframe.to_csv(
        csv_buffer,
        index=False,
        header=False,
        encoding="utf-8",
        float_format="%.17g",
        date_format="%Y-%m-%d %H:%M:%S.%f",
    )

    # Convert to a BytesIO buffer so that unicode text is properly handled.
    # See: https://github.com/pydata/pandas-gbq/issues/106
    body = csv_buffer.getvalue()
    body = body.encode("utf-8")
    return io.BytesIO(body)


def split_dataframe(dataframe, chunksize=None):
    dataframe = dataframe.reset_index(drop=True)
    if chunksize is None:
        yield 0, dataframe
        return

    remaining_rows = len(dataframe)
    total_rows = remaining_rows
    start_index = 0
    while start_index < total_rows:
        end_index = start_index + chunksize
        chunk = dataframe[start_index:end_index]
        start_index += chunksize
        remaining_rows = max(0, remaining_rows - chunksize)
        yield remaining_rows, chunk


def load_chunks(
    client,
    dataframe,
    destination_table_ref,
    chunksize=None,
    schema=None,
    location=None,
):
    job_config = bigquery.LoadJobConfig()
    job_config.write_disposition = "WRITE_APPEND"
    job_config.source_format = "CSV"
    job_config.allow_quoted_newlines = True

    # Explicit schema? Use that!
    if schema is not None:
        schema = pandas_gbq.schema.remove_policy_tags(schema)
        job_config.schema = pandas_gbq.schema.to_google_cloud_bigquery(schema)
    # If not, let BigQuery determine schema unless we are encoding the CSV files ourselves.
    elif not FEATURES.bigquery_has_from_dataframe_with_csv:
        schema = pandas_gbq.schema.generate_bq_schema(dataframe)
        schema = pandas_gbq.schema.remove_policy_tags(schema)
        job_config.schema = pandas_gbq.schema.to_google_cloud_bigquery(schema)

    chunks = split_dataframe(dataframe, chunksize=chunksize)
    for remaining_rows, chunk in chunks:
        yield remaining_rows

        if FEATURES.bigquery_has_from_dataframe_with_csv:
            client.load_table_from_dataframe(
                chunk,
                destination_table_ref,
                job_config=job_config,
                location=location,
            ).result()
        else:
            try:
                chunk_buffer = encode_chunk(chunk)
                client.load_table_from_file(
                    chunk_buffer,
                    destination_table_ref,
                    job_config=job_config,
                    location=location,
                ).result()
            finally:
                chunk_buffer.close()

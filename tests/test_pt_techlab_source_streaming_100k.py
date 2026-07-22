from __future__ import annotations

import tracemalloc

from takt.infrastructure.importers.soc_csv import CsvEventSourceReader, map_ndr


def test_soc_reader_streams_100k_without_linear_materialization(tmp_path) -> None:
    path = tmp_path / "ndr-100k.csv"
    header = "start_time,flow_id,src_host,src_ip,dst_ip,app_protocol,verdict,dns_query,bytes,incident_id\n"
    row = "2026-06-01T09:00:10Z,ndr-{i},ws-17,10.10.1.17,10.20.30.40,DNS,ALLOWED,example.test,211,BACKGROUND\n"
    with path.open("w", encoding="utf-8", newline="") as stream:
        stream.write(header)
        for index in range(100_000):
            stream.write(row.format(i=index))

    tracemalloc.start()
    count = sum(1 for _ in CsvEventSourceReader(path, map_ndr))
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert count == 100_000
    assert peak < 8 * 1024 * 1024

"""Builds a tiny GeoIP test database in the DB-IP City Lite layout. Fake data only."""
import sys
from netaddr import IPSet
from mmdb_writer import MMDBWriter, MmdbU32  # noqa: F401

out = sys.argv[1]
w = MMDBWriter(ip_version=6, database_type="DBIP-City-Lite", languages=["en"],
               description={"en": "Test data for ai-log-analyzer tests. Not real geolocation."},
               ipv4_compatible=True)
w.insert_network(IPSet(["8.8.8.0/24"]), {
    "country": {"iso_code": "ZZ", "names": {"en": "Testland"}},
    "city": {"names": {"en": "Test City"}},
})
w.insert_network(IPSet(["9.9.9.0/24"]), {
    "country": {"iso_code": "ZY", "names": {"en": "Otherland"}},
})
w.to_db_file(out)

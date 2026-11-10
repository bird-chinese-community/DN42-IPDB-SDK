import sys
from pathlib import Path

import pytest
from geoip2.database import Reader
from maxminddb import MODE_AUTO, MODE_MEMORY

FIXTURES = Path(__file__).with_name("data")


@pytest.mark.parametrize(
    "mode", [MODE_MEMORY] if sys.platform == "win32" else [MODE_MEMORY, MODE_AUTO]
)
def test_official_geoip2_readers(mode):
    for address in ["172.20.0.1", "fd42:1234::1"]:
        with Reader(FIXTURES / "country.mmdb", mode=mode) as database:
            country = database.country(address)
            assert country.country.iso_code == "US"
            assert country.country.name == "United States"
            assert country.registered_country.iso_code == "DE"
            assert country.registered_country.name == "Germany"
        with Reader(FIXTURES / "city.mmdb", mode=mode) as database:
            city = database.city(address)
            assert city.city.name == "Test City"
            assert city.subdivisions.most_specific.name == "California"
        with Reader(FIXTURES / "asn.mmdb", mode=mode) as database:
            asn = database.asn(address)
            assert asn.autonomous_system_number == 4242420001
            assert asn.autonomous_system_organization == "TestNetwork"
        with Reader(FIXTURES / "connection-type.mmdb", mode=mode) as database:
            connection = database.connection_type(address)
            assert connection.network is not None

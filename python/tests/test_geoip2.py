from pathlib import Path

from geoip2.database import Reader

FIXTURES = Path(__file__).with_name("data")


def test_official_geoip2_readers():
    for address in ["172.20.0.1", "fd42:1234::1"]:
        with Reader(FIXTURES / "country.mmdb") as database:
            country = database.country(address)
            assert country.country.iso_code == "US"
            assert country.country.name == "United States"
            assert country.registered_country.iso_code == "DE"
            assert country.registered_country.name == "Germany"
        with Reader(FIXTURES / "city.mmdb") as database:
            city = database.city(address)
            assert city.city.name == "Test City"
            assert city.subdivisions.most_specific.name == "California"
        with Reader(FIXTURES / "asn.mmdb") as database:
            asn = database.asn(address)
            assert asn.autonomous_system_number == 4242420001
            assert asn.autonomous_system_organization == "TestNetwork"
        with Reader(FIXTURES / "connection-type.mmdb") as database:
            connection = database.connection_type(address)
            assert connection.network is not None

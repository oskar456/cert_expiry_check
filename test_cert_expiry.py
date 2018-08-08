
import pytest
import datetime
from OpenSSL import crypto

import cert_expiry_check as cec


@pytest.fixture(scope="session")
def clientlist(tmpdir_factory):
    fn = tmpdir_factory.mktemp("clients").join("clientlist.yaml")
    fn.write("""
---
ipv6tun_clients:
  - id: 210
    client: oskar1
    email: ondrej@caletka.cz
  - id: 211
    client: oskar2
    email: ondrej@caletka.cz
    ticket: 123456
...
""")
    return fn


@pytest.fixture(scope="session")
def certs(tmpdir_factory):
    dn = tmpdir_factory.mktemp("certs")
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    req = crypto.X509Req()
    subj = req.get_subject()
    subj.CN = "oskar1"
    req.set_pubkey(k)
    cert = crypto.X509()
    cert.set_serial_number(1)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*24*60*60)  # 10 days
    cert.set_issuer(subj)
    cert.set_subject(subj)
    cert.set_pubkey(k)
    cert.sign(k, "sha256")
    dn.join("oskar1.crt").write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert),
    )
    subj.CN = "oskar2"
    cert.gmtime_adj_notAfter(20*24*60*60)  # 20 days
    cert.set_issuer(subj)
    cert.set_subject(subj)
    cert.sign(k, "sha256")
    dn.join("oskar2.crt").write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert),
    )
    subj.CN = "oskar3"
    cert.set_notAfter(b"20200220123456Z")
    cert.set_issuer(subj)
    cert.set_subject(subj)
    cert.sign(k, "sha256")
    dn.join("oskar3.crt").write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert),
    )
    return dn


def test_get_client_list(clientlist):
    cl = cec.get_client_list(str(clientlist))
    assert len(cl) == 2
    assert cl[0]["client"] == "oskar1"


def test_get_cert_expiry(certs):
    expdate = cec.get_cert_expiry(str(certs.join("oskar3.crt")))
    assert expdate == datetime.datetime(
        2020, 2, 20, 12, 34, 56,
        tzinfo=datetime.timezone.utc,
    )


def test_discover_expiry_times(certs):
    cl = [{"client": "oskar1"}, {"client": "oskar2"}, ]
    cec.discover_expiry_times(cl, str(certs))
    assert "expdate" in cl[0]
    assert "daystoexpire" in cl[0]
    assert cl[0]["daystoexpire"] == 9
    assert cl[1]["daystoexpire"] == 19


def test_create_email_warning():
    c = {
        "client": "oskar1",
        "expdate": datetime.datetime(
            2020, 2, 20, 12, 34, 56,
            tzinfo=datetime.timezone.utc,
        ),
        "daystoexpire": 10,
        "email": "ondrej@caletka.cz",
    }
    msg = cec.create_email_warning(c)
    assert msg["To"] == c["email"]
    assert "20. 02. 2020" in msg.get_content()
    c["ticket"] = "123456"
    msg = cec.create_email_warning(c)
    print(msg)
    assert c["email"] in msg["To"]
    assert "#123456" in msg["Subject"]


def test_send_expire_notices(clientlist, certs, capsys):
    cl = cec.get_client_list(str(clientlist))
    cec.discover_expiry_times(cl, str(certs))
    cec.send_expire_notices(cl)
    captured = capsys.readouterr()
    assert "oskar1 expires in 9 days," in captured.out
    assert "oskar2 expires in 19 days," in captured.out
    assert "#123456" in captured.out

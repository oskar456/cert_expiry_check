#!/usr/bin/env python3
# vim: ts=4 expandtab

import yaml
import datetime
import smtplib
from email.message import EmailMessage
from email.headerregistry import Address
from pathlib import Path
from operator import itemgetter

import click
from OpenSSL import crypto


def get_client_list(path="/home/ansible/clientlist.yaml"):
    return yaml.safe_load(Path(path).read_text())["ipv6tun_clients"]


def get_cert_expiry(path):
    cert = crypto.load_certificate(
        crypto.FILETYPE_PEM,
        Path(path).read_bytes(),
    )
    notafter = cert.get_notAfter().decode("ascii")
    dt = datetime.datetime.strptime(notafter, "%Y%m%d%H%M%SZ")
    return dt.replace(tzinfo=datetime.timezone.utc)


def discover_expiry_times(
        clientlist,
        certpath="/home/ansible/data/easyrsa3/pki/issued",
):
    """ Augument clientlist with expiry dates and days to expiry. """
    now = datetime.datetime.now(datetime.timezone.utc)
    for i, c in enumerate(clientlist):
        expdate = get_cert_expiry(Path(certpath) / (c["client"] + ".crt"))
        toexpire = expdate - now
        clientlist[i]["expdate"] = expdate
        clientlist[i]["daystoexpire"] = toexpire.days
    return clientlist


def create_email_warning(c):
    text = """Vážený uživateli IPv6 tunelu,

rádi bychom tě upozornili, že certifikát pro tvůj tunel {client} vyprší za
{days} dnů, {expdate:%d. %m. %Y v %H:%M UTC}. Pokud tunel už nechceš používat,
nemusíš nic dělat, jen vypni OpenVPN klienta, ať zbytečně netluče do serveru.
Pokud bys chtěl tunel používat nadále, nejdřív zopakuj dotaz u svého ISP na
podporu IPv6, aby věděli, že o to mají zákazníci zájem. Pak odpověz na tento
e-mail s žádostí o vystavení nového certifikátu.

--
Tento e-mail rozeslal automat.""".format(
        client=c.get("client"),
        days=c.get("daystoexpire"),
        expdate=c.get("expdate"),
    )
    msg = EmailMessage()
    msg["Subject"] = "Blížící se expirace certifikátu pro IPv6 tunel"
    msg["From"] = Address("vpsFree.cz IPv6 tunely", "ipv6tun", "vpsfree.cz")
    msg["To"] = c["email"]
    msg["Precedence"] = "bulk"
    if c.get("ticket"):
        ticketstr = "rt.vpsfree.cz #{}".format(c["ticket"])
        msg.replace_header("To", [msg["To"], msg["From"]])
        msg.replace_header(
            "Subject", "[{}] {}".format(
                ticketstr, msg["Subject"],
            ),
        )
        msg["RT-Ticket"] = ticketstr
    msg.set_content(text, cte="quoted-printable")
    return msg


def send_email(msg, really_send=False):
    if really_send:
        with smtplib.SMTP('localhost') as s:
            s.send_message(msg)
    else:
        print("Would send:\n{}\n---".format(msg))


def send_expire_notices(
    clientlist, maxdays=31,
    verbose=True, really_send=False,
):
    for c in clientlist:
        if verbose:
            print("Client {client} expires in {daystoexpire} days,"
                  " on {expdate:%d. %m. %Y %H:%M UTC}".format_map(c))
        if 0 < c["daystoexpire"] < maxdays:
            send_email(create_email_warning(c), really_send)


@click.command()
@click.option(
    "--clientlist",
    metavar="<yaml list of clients>",
    show_default=True,
    type=click.Path(exists=True, readable=True, dir_okay=False),
    default="/home/ansible/clientlist.yaml",
)
@click.option(
    "--certpath",
    metavar="<path to certificate directory>",
    show_default=True,
    type=click.Path(file_okay=False),
    default="/home/ansible/data/easyrsa3/pki/issued",
)
@click.option("--maxdays", type=click.INT, default=31, show_default=True)
@click.option("--really-send", is_flag=True)
@click.option("--verbose/--quiet")
def main(clientlist, certpath, maxdays, really_send, verbose):
    cl = get_client_list(clientlist)
    discover_expiry_times(cl, certpath)
    cl = sorted(cl, key=itemgetter("expdate"))
    send_expire_notices(
        cl, maxdays=maxdays, verbose=verbose,
        really_send=really_send,
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import configparser

from lib.alert import Alerter


class TestAlerter(Alerter):
    def _flush_pending(self) -> None:
        return


def _cfg() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg["Telegram"] = {"bot_token": "token", "chat_id": "chat"}
    cfg["Bluetooth"] = {"device_mac": "AA:BB:CC:DD:EE:FF"}
    cfg["Alerts"] = {"send_warning": "true", "send_info": "false", "send_critical": "true"}
    return cfg


def test_no_gateway_gets_dedicated_bluetooth_when_telegram_succeeds():
    alerter = TestAlerter(_cfg())
    alerter._telegram_send = lambda message: True
    sent = []
    alerter._bluetooth_send = sent.append

    alerter.dispatch_events([{
        "type": "no_gateway",
        "severity": "warning",
        "message": "No default gateway detected",
        "source": "quickpeek",
    }])

    assert len(sent) == 1
    assert "gateway alert" in sent[0]


def test_no_gateway_does_not_double_bluetooth_when_telegram_fails():
    alerter = TestAlerter(_cfg())
    alerter._telegram_send = lambda message: False
    alerter._enqueue = lambda message: None
    sent = []
    alerter._bluetooth_send = sent.append

    alerter.dispatch_events([{
        "type": "no_gateway",
        "severity": "warning",
        "message": "No default gateway detected",
        "source": "quickpeek",
    }])

    assert len(sent) == 1
    assert sent[0].startswith("QuickPeek alerts")


if __name__ == "__main__":
    test_no_gateway_gets_dedicated_bluetooth_when_telegram_succeeds()
    test_no_gateway_does_not_double_bluetooth_when_telegram_fails()

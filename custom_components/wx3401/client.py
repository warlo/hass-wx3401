import base64
import json
import logging
from typing import TypedDict, cast

import aiohttp

logger = logging.getLogger(__name__)


class WlanDeviceResponseDict(TypedDict):
    result: str
    result5: str


class Unauthenticated(Exception):
    pass


class WX3401ClientError(Exception):
    pass


class WX3401Client:
    def __init__(
        self,
        session: aiohttp.ClientSession,
        hostname: str,
        username: str,
        password: str,
    ) -> None:
        self.hostname = hostname
        self.username = username

        encoded_password = base64.b64encode(password.encode("ascii")).decode("ascii")
        self.password = encoded_password

        self.session = session

    async def login(self) -> None:
        res = await self.session.post(
            f"{self.hostname}/UserLogin",
            data=json.dumps(
                {
                    "Input_Account": self.username,
                    "Input_Passwd": self.password,
                    "currLang": "en",
                    "RememberPassword": 0,
                    "SHA512_password": False,
                }
            ),
        )
        if res.status != 200:
            raise WX3401ClientError("Error logging in")

    async def get_wlan_devices(
        self,
    ) -> WlanDeviceResponseDict:
        res = await self.session.get(
            f"{self.hostname}/cgi-bin/WLANTable_handle",
        )

        if res.status == 401:
            raise Unauthenticated()

        if res.status != 200:
            raise WX3401ClientError("Error getting WLANTable")

        wlan_devices = await res.json()
        if (
            isinstance(wlan_devices, dict)
            and wlan_devices.get("result") == "Invalid Username or Password"
        ):
            raise Unauthenticated()

        if not wlan_devices:
            raise WX3401ClientError("Missing clients")

        return cast(WlanDeviceResponseDict, wlan_devices[0])

    async def get_wlan_dict(self) -> dict[str, dict[str, str]]:
        try:
            device_dict = await self.get_wlan_devices()
        except Unauthenticated:
            await self.login()
            device_dict = await self.get_wlan_devices()

        wlan_2g = device_dict["result"].split()
        wlan_5g = device_dict["result5"].split()

        result_list_2g = [wlan_2g[i : i + 5] for i in range(0, len(wlan_2g), 5)]
        result_list_5g = [wlan_5g[i : i + 5] for i in range(0, len(wlan_5g), 5)]

        d2 = {
            line[0]: {result_list_2g[0][i]: line[i] for i in range(len(line))}
            for line in result_list_2g[1:]
        }
        d5 = {
            line[0]: {result_list_5g[0][i]: line[i] for i in range(len(line))}
            for line in result_list_5g[1:]
        }
        return {**d2, **d5}

    async def get_mac_addresses(self) -> list[str]:
        device_dict = await self.get_wlan_dict()
        return list(device_dict.keys())

#!/usr/bin/env python

import base64
import json
import logging
import os
from typing import TypedDict, cast

import aiohttp
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import \
    padding as asymmetric_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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
        self.use_rsa_login: bool = False

        self.aes_key: bytes | None = None
        self.rsa_pem_data: str | None = None

        self.hostname = hostname
        self.username = username

        encoded_password = base64.b64encode(password.encode("ascii")).decode("ascii")
        self.password = encoded_password

        self.session = session

    async def get_rsa_pem_data(self) -> None:
        res = await self.session.get(
            f"{self.hostname}/getRSAPublickKey",
        )
        if res.status != 200:
            raise WX3401ClientError("Error getting public-key in")

        public_key_payload: dict[str, str] = await res.json()
        self.rsa_pem_data = public_key_payload["RSAPublicKey"]

    def encrypt(self, text: str, iv: bytes | None = None) -> dict[str, str]:
        if not self.rsa_pem_data:
            raise WX3401ClientError("Missing RSA PEM Data")

        if not self.aes_key:
            self.aes_key = os.urandom(32)

        iv_bytes = iv or os.urandom(32)
        key_bytes = self.aes_key

        rsa_public_key = cast(
            rsa.RSAPublicKey,
            serialization.load_pem_public_key(self.rsa_pem_data.encode()),
        )
        encrypted_key = rsa_public_key.encrypt(
            base64.b64encode(key_bytes), padding=asymmetric_padding.PKCS1v15()
        )

        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes[:16]))
        padder = padding.PKCS7(128).padder()
        padded_t = padder.update(text.encode()) + padder.finalize()
        encryptor = cipher.encryptor()
        encrypted_content = encryptor.update(padded_t) + encryptor.finalize()

        return {
            "iv": base64.b64encode(iv_bytes).decode(),
            "key": base64.b64encode(encrypted_key).decode(),
            "content": base64.b64encode(encrypted_content).decode(),
        }

    def decrypt(self, text: str, iv: str) -> str:

        if not self.aes_key:
            raise WX3401ClientError("Missing AES Key")

        iv_bytes = base64.b64decode(iv)
        key_bytes = self.aes_key

        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes[:16]))

        decryptor = cipher.decryptor()
        decrypted_padded_content = (
            decryptor.update(base64.b64decode(text)) + decryptor.finalize()
        )
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_content = (
            unpadder.update(decrypted_padded_content) + unpadder.finalize()
        )
        return cast(str, decrypted_content.decode())

    async def login_rsa(self) -> None:
        await self.get_rsa_pem_data()

        text = json.dumps(
            {
                "Input_Account": self.username,
                "Input_Passwd": self.password,
                "currLang": "en",
                "RememberPassword": 0,
                "SHA512_password": False,
            }
        ).replace(
            " ", ""
        )  # Remove spaces to conform identically

        encrypted_payload = self.encrypt(text)

        res = await self.session.post(
            f"{self.hostname}/UserLogin",
            data=json.dumps(encrypted_payload),
        )
        if res.status != 200:
            try:
                res_json = await res.json()
            except Exception:
                res_json = {"msg": "Failed getting json"}

            raise WX3401ClientError(f"Error logging in: {res_json}")

        self.use_rsa_login = True

    async def login(self) -> None:
        if self.use_rsa_login:
            return await self.login_rsa()

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
            try:
                error = await res.json()

                # Login with encryption
                if error["result"] == "Decrypt Fail":
                    return await self.login_rsa()
            except Exception:
                pass

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

        # If WLANTable is encrypted it has "content" as a key
        if wlan_devices.get("content"):
            wlan_devices = json.loads(
                self.decrypt(wlan_devices["content"], iv=wlan_devices["iv"])
            )

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


if __name__ == "__main__":
    import asyncio

    import aiohttp

    # Local test

    hostname = input("hostname:").strip() or "http://192.168.1.2"
    username = input("username:").strip() or "admin"
    password = input("password:").strip()
    print("h", hostname, username, password)

    async def fetch() -> None:
        jar = aiohttp.CookieJar(unsafe=True)
        session = aiohttp.ClientSession(cookie_jar=jar)
        client = WX3401Client(
            session=session, hostname=hostname, username=username, password=password
        )
        await client.login()
        await client.get_wlan_dict()

    asyncio.run(fetch())

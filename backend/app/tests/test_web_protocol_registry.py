import asyncio
import inspect

import httpx

from app.remote_gateway import web_auth
from app.remote_gateway.web_protocol_registry import (
    authenticate_registered_web_protocol,
    registered_web_protocol_families,
)


def test_generic_web_auth_has_no_direct_vendor_protocol_dependency():
    source = inspect.getsource(web_auth)
    assert "tp_link_mr_web_auth" not in source
    assert "authenticate_registered_web_protocol" in source


def test_registry_skips_adapter_when_credential_mode_is_not_supported():
    async def scenario():
        page = "cgi/getParm cgi/login tpEncrypt AESEncrypt Iencryptor"
        async with httpx.AsyncClient(base_url="http://192.0.2.44") as client:
            result = await authenticate_registered_web_protocol(
                client,
                credential_mode="USERNAME_PASSWORD",
                login_page_text=page,
                password="NOT_USED",
            )
            assert result is None

    asyncio.run(scenario())


def test_builtin_registry_exposes_protocol_family_not_device_model():
    families = registered_web_protocol_families()
    assert "TP_LINK_MR_RSA_AES" in families
    assert all("MR600" not in family.upper() for family in families)

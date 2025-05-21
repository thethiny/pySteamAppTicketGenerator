import time
from steam.client import SteamClient
from steam.enums import EResult
import asyncio


class SteamAppTicket:

    def __init__(self, semaphore = None) -> None:
        if isinstance(semaphore, asyncio.Semaphore):
            self.semaphore = semaphore
        elif isinstance(semaphore, int):
            self.semaphore = asyncio.Semaphore(semaphore)
        else:
            self.semaphore = asyncio.Semaphore(4)

    async def get_encrypted_ticket(
        self,
        username,
        password=None,
        auth_code=None,
        two_factor_code=None,
        login_key=None,
        app_id: int = 480
    ):
        async with self.semaphore:
            loop = asyncio.get_event_loop()
            result = {}

            def worker():
                client = SteamClient()
                start_time = time.monotonic()
                timeout = 10

                @client.on(client.EVENT_LOGGED_ON)  # type: ignore
                def handle_login():
                    print("Log in event")
                    try:
                        ticket = client.get_encrypted_app_ticket(app_id, b"")
                        result["status"] = "ok"
                        result["ticket"] = (
                            ticket.encrypted_app_ticket.SerializeToString().hex()
                        )
                    except Exception as e:
                        result["status"] = "error"
                        result["error"] = str(e)
                    finally:
                        client.disconnect()

                @client.on(client.EVENT_ERROR)  # type: ignore
                def handle_error(result_code):
                    error = EResult(result_code)
                    result["status"] = "error"
                    if error == EResult.InvalidPassword:
                        result["error"] = "Incorrect Password!"
                    elif error == EResult.AccountLogonDenied:
                        result["error"] = "Login Denied!"
                        result["status"] = "email"
                    elif error == EResult.InvalidLoginAuthCode:
                        result["error"] = "Incorrect Login Code!"
                        result["status"] = "email"
                    elif error == EResult.TwoFactorCodeMismatch:
                        result["error"] = "Incorrect Login Code!"
                        result["status"] = "2fa"
                    elif error == EResult.AccountLoginDeniedNeedTwoFactor:
                        result["error"] = "Steam Guard Required!"
                        result["status"] = "2fa"
                    else:
                        result["error"] = f"Steam error: {error.name}"
                    print(f"Error event: {result['error']}")
                    client.disconnect()

                login_args = {"username": username}
                if login_key:
                    login_args["login_key"] = login_key
                else:
                    login_args["password"] = password
                    if two_factor_code:
                        login_args["two_factor_code"] = two_factor_code
                    if auth_code:
                        login_args["auth_code"] = auth_code

                if not login_key and not login_args["password"]:
                    raise ValueError(f"Password or Login Key required!")

                client.login(**login_args)
                while not result and (time.monotonic() - start_time < timeout):
                    client.sleep(0.2)
                if not result:  # Timeout
                    result["status"] = "error"
                    result["error"] = "Timed out waiting for steam to respond"

                return result

            return await loop.run_in_executor(None, worker)

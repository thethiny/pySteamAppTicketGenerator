import logging
import os
import time
from ctypes import POINTER, byref, cast, create_string_buffer, sizeof
from ctypes import (
    Structure,
    WinDLL,
    c_bool,
    c_char_p,
    c_int,
    c_uint32,
    c_uint64,
    c_void_p,
)
from enum import IntEnum
from typing import Type


class EncryptedAppTicketResponse_t(Structure):
    _fields_ = [("m_eResult", c_int)]  # EResult is a 32-bit int
    _id = 154


class EResult(IntEnum):
    k_EResultOK = 1
    k_EResultFail = 2
    k_EResultNoConnection = 3
    k_EResultLimitExceeded = 25
    k_EResultDuplicateRequest = 29


class SteamAppTicket:
    def __init__(self, app_id: str = "", dll_path: str = ""):
        self.dll_path = dll_path or os.path.join(os.getcwd(), "steam_api64.dll")
        self.api: WinDLL
        self.h_user = None
        self.h_pipe = None
        self.client = None
        self.user = None
        self.interface_ver = b"SteamUser023"
        self.used_app_id = False
        self.ticket_requested = False

        if app_id:
            try:
                with open("steam_appid.txt", "w") as f:
                    f.write(app_id)
                self.used_app_id = True
            except Exception:
                raise ValueError("Couldn't generate App Id. If steam_appid is open, please close it.")

        self.init = False

    def initialize_apis(self):
        self._load_dll()
        self._init_steam()
        self._get_interfaces()
        self._define_functions()
        self.init = True

    def _load_dll(self):
        self.api = WinDLL(self.dll_path)

    def _init_steam(self):
        if not self.api or not self.api.SteamAPI_Init():
            raise RuntimeError("SteamAPI_Init failed")

        self.api.SteamAPI_GetHSteamUser.restype = c_int
        self.api.SteamAPI_GetHSteamPipe.restype = c_int
        self.h_user = self.api.SteamAPI_GetHSteamUser()
        self.h_pipe = self.api.SteamAPI_GetHSteamPipe()

        if not self.h_user or not self.h_pipe:
            raise RuntimeError("Invalid Steam handles")

    def _get_interfaces(self):
        self.api.SteamClient.restype = c_void_p
        self.client = self.api.SteamClient()
        if not self.client:
            raise RuntimeError("SteamClient failed")

        # ISteamUser
        self.api.SteamAPI_ISteamClient_GetISteamUser.argtypes = [
            c_void_p,
            c_int,
            c_int,
            c_char_p,
        ]
        self.api.SteamAPI_ISteamClient_GetISteamUser.restype = c_void_p
        self.user = self.api.SteamAPI_ISteamClient_GetISteamUser(
            self.client, self.h_user, self.h_pipe, self.interface_ver
        )
        if not self.user:
            raise RuntimeError("Failed to get ISteamUser interface")

        # ISteamUtils
        self.api.SteamAPI_ISteamClient_GetISteamUtils.argtypes = [
            c_void_p,
            c_int,
            c_char_p,
        ]
        self.api.SteamAPI_ISteamClient_GetISteamUtils.restype = c_void_p
        self.utils = self.api.SteamAPI_ISteamClient_GetISteamUtils(
            self.client, self.h_pipe, b"SteamUtils009"
        )
        if not self.utils:
            raise RuntimeError("Failed to get ISteamUtils interface")

        # ISteamFriends
        self.api.SteamAPI_ISteamClient_GetISteamFriends.argtypes = [
            c_void_p,
            c_int,
            c_int,
            c_char_p,
        ]
        self.api.SteamAPI_ISteamClient_GetISteamFriends.restype = c_void_p
        self.friends = self.api.SteamAPI_ISteamClient_GetISteamFriends(
            self.client, self.h_user, self.h_pipe, b"SteamFriends015"
        )

    def _define_functions(self):
        self.api.SteamAPI_ISteamUser_GetEncryptedAppTicket.argtypes = [
            c_void_p,
            c_void_p,
            c_int,
            POINTER(c_uint32),
        ]
        self.api.SteamAPI_ISteamUser_GetEncryptedAppTicket.restype = c_bool

        self.api.SteamAPI_ISteamUser_RequestEncryptedAppTicket.argtypes = [
            c_void_p,
            c_void_p,
            c_int,
        ]
        self.api.SteamAPI_ISteamUser_RequestEncryptedAppTicket.restype = c_uint64

        self.api.SteamAPI_ISteamUtils_IsAPICallCompleted.argtypes = [
            c_void_p,
            c_uint64,
            POINTER(c_bool),
        ]
        self.api.SteamAPI_ISteamUtils_IsAPICallCompleted.restype = c_bool

        self.api.SteamAPI_ISteamUtils_GetAPICallResult.argtypes = [
            c_void_p,
            c_uint64,
            c_void_p,
            c_int,
            c_int,
            POINTER(c_bool),
        ]
        self.api.SteamAPI_ISteamUtils_GetAPICallResult.restype = c_bool

        self.api.SteamAPI_ISteamUser_GetSteamID.argtypes = [c_void_p]
        self.api.SteamAPI_ISteamUser_GetSteamID.restype = c_uint64

        self.api.SteamAPI_ISteamFriends_GetPersonaName.argtypes = [c_void_p]
        self.api.SteamAPI_ISteamFriends_GetPersonaName.restype = c_char_p

    def get_steam_id(self):
        return self.api.SteamAPI_ISteamUser_GetSteamID(self.user)

    def get_steam_name(self):
        return self.api.SteamAPI_ISteamFriends_GetPersonaName(self.friends).decode(
            "utf-8"
        )

    def get_encrypted_app_ticket(self,):  
        if not self.init:
            raise ValueError(f"Please initialize the client first!")

        if not self.ticket_requested:
            logging.getLogger("SteamAppTicket").warning(f"You should call {self.request_and_wait_for_encrypted_app_ticket.__name__} first! May fail otherwise.")

        buf_size = 2048
        buffer = create_string_buffer(buf_size)
        ticket_size = c_uint32()

        success = self.api.SteamAPI_ISteamUser_GetEncryptedAppTicket(
            self.user,
            buffer,
            buf_size,
            byref(ticket_size),
        )

        if not success:
            raise RuntimeError("GetEncryptedAppTicket failed")

        return buffer.raw[: ticket_size.value]

    def request_and_wait_for_encrypted_app_ticket(self, data: bytes = b""):
        if not self.init:
            raise ValueError(f"Please initialize the client first!")
        request_id = self.request_encrypted_app_ticket(data)
        result_struct = self.wait_for_call_result(
            request_id,
            EncryptedAppTicketResponse_t,
            sizeof(EncryptedAppTicketResponse_t),
        )
        request_state = EResult(result_struct.m_eResult)

        if request_state != EResult.k_EResultOK:
            raise RuntimeError(f"Steam Login Failed: {request_state.name}")
        logging.getLogger("SteamAppTicket").info("Ticket Received")
        self.ticket_requested = True

    def request_encrypted_app_ticket(self, data: bytes = b""):
        if not self.init:
            raise ValueError(f"Please initialize the client first!")
        return self.api.SteamAPI_ISteamUser_RequestEncryptedAppTicket(
            self.user, cast(c_char_p(data), c_void_p), len(data)
        )

    def wait_for_call_result(
        self, call_id, callback_type: Type[Structure], struct_size=32, poll_interval=0.5
    ):
        if not self.init:
            raise ValueError(f"Please initialize the client first!")
        io_failure = c_bool(False)
        while not self.api.SteamAPI_ISteamUtils_IsAPICallCompleted(
            self.utils, call_id, byref(io_failure)
        ):
            time.sleep(poll_interval)

        result_buffer = create_string_buffer(struct_size)

        success = self.api.SteamAPI_ISteamUtils_GetAPICallResult(
            self.utils,
            call_id,
            result_buffer,
            struct_size,
            callback_type._id,
            byref(io_failure),
        )

        if not success or io_failure.value:
            raise RuntimeError(
                "SteamAPI_GetAPICallResult failed or IO failure occurred"
            )

        result_struct = self.parse_callback_response(callback_type, result_buffer)
        return result_struct

    @classmethod
    def parse_callback_response(cls, type: Type[Structure], buffer):
        return type.from_buffer_copy(buffer)

    def shutdown(self):
        if self.used_app_id:
            try:
                os.remove("steam_appid.txt")
            except Exception:
                pass

        if self.api:
            try:
                self.api.SteamAPI_Shutdown()
            except Exception:
                pass


# Example usage
if __name__ == "__main__":
    try:
        steam = SteamAppTicket()
        steam.initialize_apis()
        steam.request_and_wait_for_encrypted_app_ticket()
        encrypted_ticket = steam.get_encrypted_app_ticket()
        print("Encrypted Ticket (hex):", encrypted_ticket.hex())
    except Exception as e:
        print("Error:", e)
    finally:
        if "steam" in locals():
            steam.shutdown()

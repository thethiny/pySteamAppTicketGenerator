from client import SteamAppTicket, SteamTicketDecryptor

spacewar_key = bytes([
    0xed, 0x93, 0x86, 0x07, 0x36, 0x47, 0xce, 0xa5,
    0x8b, 0x77, 0x21, 0x49, 0x0d, 0x59, 0xed, 0x44,
    0x57, 0x23, 0xf0, 0xf6, 0x6e, 0x74, 0x14, 0xe1,
    0x53, 0x3b, 0xa3, 0x3c, 0xd8, 0x03, 0xbd, 0xbd
])

if __name__ == "__main__":
    steam = SteamAppTicket(app_id=480, dll_path="./steam_api64.dll")
    steam.initialize_apis()
    user_id = steam.get_steam_id()
    steam.request_and_wait_for_encrypted_app_ticket()
    encrypted_ticket = steam.get_encrypted_app_ticket()
    print("Encrypted Ticket:", encrypted_ticket.hex())
    steam.shutdown()

    dec = SteamTicketDecryptor(480, "./sdkencryptedappticket64.dll", key=spacewar_key)
    decrypted_ticket = dec.decrypt_ticket(encrypted_ticket)
    ticket_app_id, ticket_user_id = dec.validate_ticket(decrypted_ticket, user_id)
    print("Decrypted Ticket:", decrypted_ticket.hex())
    print(f"Ticket for user {ticket_user_id} and app {ticket_app_id}")

# logger.py

import os
import datetime


class PacketLogger:

    def __init__(self):

        os.makedirs("captures", exist_ok=True)

        self.file = "captures/packets.log"

    def write(self, message):

        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with open(self.file, "a", encoding="utf-8") as log:

            log.write(f"[{now}] {message}\n")
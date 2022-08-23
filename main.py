from threading import Thread
from time import sleep
import configparser

from bot_commands import *
from cve import *


def get_api_keys():
    config = configparser.ConfigParser()
    config.read("params.conf")

    return config["nvd"]["API_KEY"], config["telegram"]["API_KEY"]


def notify_worker():
    while True:
        sleep(60*60*24)
        notify_users()


def main():
    nvd_key, telegram_key = get_api_keys()
    setup_bot(nvd_key, telegram_key)
    new_thread = Thread(target=notify_worker, args={})
    new_thread.start()


if __name__ == '__main__':
    main()

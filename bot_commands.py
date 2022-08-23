import telegram
from telegram.update import Update
from telegram.ext.callbackcontext import CallbackContext
from telegram.ext.updater import Updater
from telegram.ext.commandhandler import CommandHandler
from telegram.ext.messagehandler import MessageHandler
from telegram.ext.filters import Filters
from typing import List, Dict
from datetime import datetime, timedelta, timezone
import html

from cve import *


class User:
    def __init__(self):
        self.is_active = False
        self.keywords: List[str] = []
        self.is_waiting_keywords = False


# List of users
users: Dict[int, User] = {}
nvd_key: str = ""
bot: telegram.Bot


# TODO: move to OOP
def setup_bot(nvd_key_api, telegram_key):
    global nvd_key, bot
    nvd_key = nvd_key_api
    updater = Updater(telegram_key, use_context=True)
    bot = updater.bot

    updater.dispatcher.add_handler(CommandHandler('start', start))
    updater.dispatcher.add_handler(CommandHandler('start_monitor', start_monitor))
    updater.dispatcher.add_handler(CommandHandler('stop_monitor', stop_monitor))
    updater.dispatcher.add_handler(CommandHandler('get_latest', get_latest))
    updater.dispatcher.add_handler(CommandHandler('edit_keywords', edit_keywords))
    updater.dispatcher.add_handler(MessageHandler(Filters.text, edit_keywords_data))
    # Filters out unknown commands
    updater.dispatcher.add_handler(MessageHandler(Filters.command, unknown))

    updater.start_polling()

    
def notify_users():
    now = datetime.now(tz=timezone.utc)
    start_date = now - timedelta(days=1)

    for chat_id, user in users.items():
        # User didn't start monitoring
        if not user.is_active:
            continue

        count = 0
        bot.send_message(chat_id, "⚠️Warning: send only first 50 entries!")
        for keyword in user.keywords:
            cves = get_list_by_date(nvd_key, start_date, now, modified=True, keyword=keyword)
            bot.send_message(chat_id, f"📜 Sending cves for keyword \"{keyword}\"")
            for cve in cves:
                count += 1
                formatted_text = _format_cve_output(cve)
                bot.send_message(chat_id, formatted_text,
                                 parse_mode=telegram.ParseMode.HTML)
        bot.send_message(chat_id, f"❎ Today you received {count} cve.\nHave a nice day!")


def _get_user(user_id: int):
    global users
    user_data = users.get(user_id, None)
    if user_data is None:
        # Initialize new user
        user_data = User()
    return user_data


def _format_cve_output(cve: CVE):
    description = html.escape(cve.description)
    formatted_text = f"   ➡➡️➡️  {cve.cve_id}   ⬅️⬅️⬅️\n" \
                     f"🔰 Severity: <b>{cve.severity}</b>\n" \
                     f"🏅 Score: <b>{cve.score}</b>\n" \
                     f"📢 Description: {description}\n\n" \
                     f"💡 References: \n"
    for ref in cve.references:
        type = ref.type if ref.type else "Unknown"
        formatted_text += f"-  <a href=\"{ref.url}\">{type}</a>\n"

    return formatted_text


def start(update: Update, context: CallbackContext):
    print(context.user_data)
    print(context.chat_data)
    print(update.effective_chat.id)
    print(update.effective_user.username)
    update.message.reply_text(
        "Welcome here!\nTo start monitoring run command: /start_monitor\n"
        "To edit monitoring keywords run: /edit_keywords")
    users[update.effective_chat.id] = User()


def start_monitor(update: Update, context: CallbackContext):
    global users
    user_data = _get_user(update.effective_chat.id)

    user_data.is_active = True
    users[update.effective_chat.id] = user_data
    update.message.reply_text("✅ You successfully joined the daily feed")


def stop_monitor(update: Update, context: CallbackContext):
    global users
    user_data = users.get(update.effective_chat.id, None)
    if user_data is not None:
        user_data.is_active = False
        users[update.effective_chat.id] = user_data
    update.message.reply_text("💔 You unsubscribed(")


def get_latest(update: Update, context: CallbackContext):
    now = datetime.now(tz=timezone.utc)
    start_date = now-timedelta(days=30)
    cves = get_list_by_date(nvd_key, start_date, now, modified=False, severity="CRITICAL")
    update.message.reply_text("⚠️Warning: send only first 50 entries!")
    for cve in cves:
        formatted_text = _format_cve_output(cve)
        update.message.reply_text(formatted_text,
                                  parse_mode=telegram.ParseMode.HTML)


def edit_keywords(update: Update, context: CallbackContext):
    global users
    user_data = _get_user(update.effective_chat.id)

    update.message.reply_text(f"❗️ Enter your new search keywords separated by comma\n `{','.join(user_data.keywords)}`",
                              parse_mode=telegram.ParseMode.MARKDOWN)
    user_data.is_waiting_keywords = True
    users[update.effective_chat.id] = user_data


def edit_keywords_data(update: Update, context: CallbackContext):
    global users
    user_data = _get_user(update.effective_chat.id)
    if not user_data.is_waiting_keywords:
        update.message.reply_text("❗️ If you want to edit search keywords, use /edit_keywords")
        return
    user_data.keywords = [i.strip() for i in update.message.text.split(",")]
    user_data.is_waiting_keywords = False
    update.message.reply_text(f"✅ Updated keywords to\n `{','.join(user_data.keywords)}`",
                              parse_mode=telegram.ParseMode.MARKDOWN)
    users[update.effective_chat.id] = user_data


def unknown(update: Update, context: CallbackContext):
    update.message.reply_text(
        "❌ Sorry '%s' is not a valid command" % update.message.text)
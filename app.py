import telebot
from telebot import types
import subprocess
import os
import re
import sys
import importlib
import time
import shutil
import requests
import json
import hashlib
import threading

TOKEN = '7792978424:AAGeZbhbH_HKvFUMCO03s9RLM1sS8QYxd34'
bot = telebot.TeleBot(TOKEN)

admin_id = 6924216753
max_file_size = 100 * 1024 * 1024

banned_users = set()
users_start_status = {}
user_files = {}
bot_processes = {}
bot_info_messages = {}
pending_reviews = {}
waiting_for_file = set()
progress_messages = {}

# حالات الإدارة
admin_states = {}
is_broadcasting = False
maintenance_mode = False

CHANNEL_USERNAME = '@TP_Q_T'

base_dir = 'uploaded_bots'
os.makedirs(base_dir, exist_ok=True)

# المكتبات القياسية + المكتبات المثبتة مسبقاً على السيرفر
standard_libs = {
    'os', 'sys', 're', 'math', 'random', 'datetime', 'time', 'json', 'subprocess',
    'logging', 'threading', 'functools', 'itertools', 'collections', 'typing',
    'pathlib', 'http', 'unittest', 'urllib', 'base64', 'shutil', 'getpass',
    'hashlib', 'statistics', 'inspect', 'socket', 'contextlib', 'argparse',
    'string', 'abc', 'array', 'ast', 'asyncio', 'binascii', 'calendar', 'cgi',
    'cgitb', 'codecs', 'copy', 'csv', 'ctypes', 'decimal', 'difflib', 'dis',
    'doctest', 'enum', 'errno', 'faulthandler', 'gc', 'glob', 'gzip', 'io',
    'keyword', 'locale', 'lzma', 'mailbox', 'marshal', 'mmap', 'multiprocessing',
    'operator', 'pickle', 'pprint', 'queue', 'select', 'shelve', 'signal',
    'smtplib', 'sqlite3', 'ssl', 'struct', 'tempfile', 'textwrap', 'traceback',
    'turtle', 'uuid', 'warnings', 'weakref', 'xml', 'zipfile', 'zlib',
    'types', 'importlib', 'importlib.util', 'fractions', 'html', 'email',
    'webbrowser', 'wave', 'sqlite3', 'readline', 'rlcompleter', 'dbm', 'ensurepip',
    'venv', 'tkinter', 'idlelib', 'pydoc', 'doctest', 'profile', 'cProfile',
    'pstats', 'timeit', 'trace', 'tracemalloc', 'linecache', 'pickletools',
    'code', 'codeop', 'pdb', 'platform', 'sysconfig', 'site', 'builtins',
    '__future__', 'atexit', 'abc', 'collections.abc', 'contextvars', 'dataclasses',
    'enum', 'inspect', 'types', 'typing', 'weakref', 'copyreg', 'reprlib',
    'shelve', 'marshal', 'dbm', 'sqlite3', 'xmlrpc', 'ipaddress', 'concurrent',
    'asyncio', 'multiprocessing', 'threading', 'queue', 'selectors', 'subprocess',
    'os.path', 'pathlib', 'fnmatch', 'linecache', 'tempfile', 'shutil',
    'glob', 'bz2', 'lzma', 'gzip', 'zipfile', 'tarfile', 'csv', 'configparser',
    'logging', 'getopt', 'argparse', 'getpass', 'curses', 'plistlib', 'json',
    'xml', 'html', 'xml.etree', 'socketserver', 'http', 'urllib', 'ftplib',
    'poplib', 'imaplib', 'nntplib', 'smtplib', 'smtpd', 'telnetlib', 'uuid',
    'sockets', 'ssl', 'select', 'selectors', 'asyncore', 'asynchat', 'signal',
    'mmap', 'errno', 'ctypes', 'threading', 'multiprocessing', 'concurrent',
    'subprocess', 'os', 'io', 'time', 'optparse', 'locale', 'calendar', 'collections',
    'heapq', 'bisect', 'array', 'sched', 'queue', 'struct', 'copy', 'pprint',
    'reprlib', 'enum', 'graphlib', 'numbers', 'math', 'cmath', 'decimal', 'fractions',
    'random', 'statistics', 'itertools', 'functools', 'operator', 'pathlib',
    'fileinput', 'stat', 'filecmp', 'tempfile', 'glob', 'fnmatch', 'linecache',
    'shutil', 'macpath', 'pickle', 'copyreg', 'shelve', 'marshal', 'dbm', 'sqlite3',
    'zlib', 'gzip', 'bz2', 'lzma', 'zipfile', 'tarfile', 'csv', 'configparser',
    'netrc', 'xdrlib', 'plistlib', 'hashlib', 'hmac', 'secrets', 'os', 'io',
    'time', 'argparse', 'getopt', 'logging', 'getpass', 'curses', 'platform',
    'errno', 'ctypes', 'select', 'selectors', 'socket', 'ssl', 'signal', 'threading',
    'multiprocessing', 'subprocess', 'os.path', 'pathlib', 'fnmatch', 'linecache',
    'tempfile', 'shutil', 'glob', 'bz2', 'lzma', 'gzip', 'zipfile', 'tarfile',
    'csv', 'configparser', 'netrc', 'xdrlib', 'plistlib', 'hashlib', 'hmac',
    'secrets', 'os', 'io', 'time', 'argparse', 'getopt', 'logging', 'getpass',
    'curses', 'platform', 'errno', 'ctypes', 'select', 'selectors', 'socket',
    'ssl', 'signal', 'threading', 'multiprocessing', 'subprocess',
    # المكتبات المثبتة مسبقاً على السيرفر
    'requests', 'telebot', 'pytelegrambotapi'
}

special_lib_mappings = {
    'google': 'google-cloud',
    'google.generativeai': 'google-generativeai',
    'google.cloud': 'google-cloud',
    'google.api': 'google-api-python-client',
    'cv2': 'opencv-python',
    'PIL': 'pillow',
    'sklearn': 'scikit-learn',
    'bs4': 'beautifulsoup4',
    'yaml': 'pyyaml',
    'dateutil': 'python-dateutil',
    'serial': 'pyserial',
    'crypto': 'pycryptodome',
    'telebot.types': None,
    'pyrolistener': 'pyrolistener @ git+https://github.com/SSUU-SS/pyrolistener',
    'pyrogram': {
        'name': 'pyrogram',
        'install_cmd': [sys.executable, "-m", "pip", "install", "pyrogram", "--no-use-pep517"]
    },
    '_curses': None,
    'win32api': None,

    # مكتبات التليجرام الشائعة
    'telethon': 'telethon',
    'pyrogram.client': 'pyrogram',
    'pyrogram.errors': 'pyrogram',
    'pyrogram.types': 'pyrogram',
    'telegram.ext': 'python-telegram-bot',
    'telegram': 'python-telegram-bot',
    'tgcrypto': 'tgcrypto',
    'tgspeedup': 'tgspeedup',
    'aiogram': 'aiogram',
    'pytelegrambotapi': None,  # مثبتة مسبقاً
    'requests': None,  # مثبتة مسبقاً

    # مكتبات الويب والطلب
    'aiohttp': 'aiohttp',
    'httpx': 'httpx',
    'urllib3': 'urllib3',
    'flask': 'flask',
    'django': 'django',
    'fastapi': 'fastapi',
    'sanic': 'sanic',
    'quart': 'quart',
    'tornado': 'tornado',
    'bottle': 'bottle',
    'pyramid': 'pyramid',
    'starlette': 'starlette',
    'uvicorn': 'uvicorn',
    'gunicorn': 'gunicorn',

    # مكتبات قواعد البيانات
    'sqlalchemy': 'sqlalchemy',
    'psycopg2': 'psycopg2-binary',
    'pymysql': 'pymysql',
    'mysql.connector': 'mysql-connector-python',
    'redis': 'redis',
    'pymongo': 'pymongo',
    'motor': 'motor',
    'aioredis': 'aioredis',
    'asyncpg': 'asyncpg',
    'sqlite3': None,  # مكتبة قياسية
    'dataset': 'dataset',
    'peewee': 'peewee',
    'pony': 'pony',
    'tortoise': 'tortoise-orm',
    'ormar': 'ormar',

    # مكتبات التعامل مع البيانات
    'numpy': 'numpy',
    'pandas': 'pandas',
    'matplotlib': 'matplotlib',
    'seaborn': 'seaborn',
    'openpyxl': 'openpyxl',
    'xlsxwriter': 'xlsxwriter',
    'plotly': 'plotly',
    'bokeh': 'bokeh',
    'scipy': 'scipy',
    'sympy': 'sympy',
    'statsmodels': 'statsmodels',
    'polars': 'polars',
    'dask': 'dask',
    'vaex': 'vaex',

    # مكتبات الذكاء الاصطناعي والتعلم الآلي
    'tensorflow': 'tensorflow',
    'torch': 'torch',
    'transformers': 'transformers',
    'diffusers': 'diffusers',
    'langchain': 'langchain',
    'openai': 'openai',
    'huggingface_hub': 'huggingface_hub',
    'keras': 'keras',
    'sklearn': 'scikit-learn',
    'xgboost': 'xgboost',
    'lightgbm': 'lightgbm',
    'catboost': 'catboost',
    'spacy': 'spacy',
    'nltk': 'nltk',
    'gensim': 'gensim',
    'allennlp': 'allennlp',
    'stanza': 'stanza',
    'fasttext': 'fasttext',
    'opencv': 'opencv-python',
    'mediapipe': 'mediapipe',
    'face_recognition': 'face-recognition',
    'pytorch_lightning': 'pytorch-lightning',
    'torchvision': 'torchvision',
    'torchaudio': 'torchaudio',
    'jax': 'jax',
    'flax': 'flax',
    'optuna': 'optuna',
    'ray': 'ray',

    # مكتبات معالجة الصوت والصورة
    'PIL': 'pillow',
    'Pillow': 'pillow',
    'opencv': 'opencv-python',
    'cv2': 'opencv-python',
    'imageio': 'imageio',
    'scikit_image': 'scikit-image',
    'moviepy': 'moviepy',
    'pydub': 'pydub',
    'librosa': 'librosa',
    'soundfile': 'soundfile',
    'pyaudio': 'pyaudio',
    'ffmpeg': 'ffmpeg-python',
    'pygame': 'pygame',

    # مكتبات الأتمتة والمهام
    'selenium': 'selenium',
    'pyautogui': 'pyautogui',
    'schedule': 'schedule',
    'apscheduler': 'apscheduler',
    'celery': 'celery',
    'luigi': 'luigi',
    'airflow': 'apache-airflow',
    'fabric': 'fabric',
    'invoke': 'invoke',
    'paramiko': 'paramiko',
    'psutil': 'psutil',

    # مكتبات الأمان والتشفير
    'cryptography': 'cryptography',
    'paramiko': 'paramiko',
    'bcrypt': 'bcrypt',
    'pyjwt': 'pyjwt',
    'oauthlib': 'oauthlib',
    'requests_oauthlib': 'requests-oauthlib',
    'authlib': 'Authlib',
    'passlib': 'passlib',
    'hashlib': None,  # مكتبة قياسية
    'ssl': None,      # مكتبة قياسية

    # مكتبات المساعدة والتطوير
    'dotenv': 'python-dotenv',
    'tqdm': 'tqdm',
    'rich': 'rich',
    'loguru': 'loguru',
    'colorama': 'colorama',
    'python_dateutil': 'python-dateutil',
    'pytz': 'pytz',
    'click': 'click',
    'fire': 'fire',
    'typer': 'typer',
    'prompt_toolkit': 'prompt-toolkit',
    'pygments': 'pygments',
    'progress': 'progress',
    'alive_progress': 'alive-progress',
    'debugpy': 'debugpy',
    'ipdb': 'ipdb',
    'pdbpp': 'pdbpp',

    # مكتبات التعامل مع النصوص
    'nltk': 'nltk',
    'spacy': 'spacy',
    'gensim': 'gensim',
    'googletrans': 'googletrans',
    'textblob': 'textblob',
    'ftfy': 'ftfy',
    'unidecode': 'unidecode',
    'regex': 'regex',
    'fuzzywuzzy': 'fuzzywuzzy',
    'python_levenshtein': 'python-Levenshtein',
    'rapidfuzz': 'rapidfuzz',
    'sentencepiece': 'sentencepiece',
    'tokenizers': 'tokenizers',

    # مكتبات التعامل مع الملفات
    'rarfile': 'rarfile',
    'py7zr': 'py7zr',
    'pypdf2': 'pypdf2',
    'pdfminer': 'pdfminer.six',
    'pdfplumber': 'pdfplumber',
    'pyexcel': 'pyexcel',
    'openpyxl': 'openpyxl',
    'xlrd': 'xlrd',
    'xlwt': 'xlwt',
    'xlsxwriter': 'xlsxwriter',
    'python_docx': 'python-docx',
    'pypandoc': 'pypandoc',
    'msoffcrypto': 'msoffcrypto-tool',
    'pywin32': 'pywin32',

    # مكتبات التعرف الضوئي على الحروف (OCR)
    'pytesseract': 'pytesseract',
    'easyocr': 'easyocr',
    'tesserocr': 'tesserocr',
    'kraken': 'kraken',
    'ocrmypdf': 'ocrmypdf',

    # مكتبات الجداول الزمنية
    'pytz': 'pytz',
    'dateparser': 'dateparser',
    'arrow': 'arrow',
    'pendulum': 'pendulum',
    'maya': 'maya',
    'delorean': 'delorean',
    'times': 'times',

    # مكتبات التخزين السحابي
    'boto3': 'boto3',
    'google.cloud.storage': 'google-cloud-storage',
    'dropbox': 'dropbox',
    'pydrive': 'PyDrive',
    'azure.storage': 'azure-storage-blob',
    'minio': 'minio',
    's3fs': 's3fs',
    'gcsfs': 'gcsfs',
    'paramiko': 'paramiko',

    # مكتبات الأنظمة والخدمات
    'psutil': 'psutil',
    'systemd': 'systemd-python',
    'docker': 'docker',
    'kubernetes': 'kubernetes',
    'fabric': 'fabric',
    'ansible': 'ansible',
    'salt': 'salt',
    'supervisor': 'supervisor',
    'gunicorn': 'gunicorn',
    'uvicorn': 'uvicorn',
    'waitress': 'waitress',

    # مكتبات الواجهات الرسومية
    'pyqt5': 'pyqt5',
    'tkinter': None,  # مكتبة قياسية
    'pygame': 'pygame',
    'kivy': 'kivy',
    'wx': 'wxPython',
    'pyglet': 'pyglet',
    'pygobject': 'pygobject',
    'pyside2': 'pyside2',
    'pyside6': 'pyside6',
    'pyforms': 'pyforms',
    'remi': 'remi',
    'dearpygui': 'dearpygui',
    'pywebview': 'pywebview',

    # مكتبات التحليل والتنقيب
    'scrapy': 'scrapy',
    'beautifulsoup': 'beautifulsoup4',
    'lxml': 'lxml',
    'selenium': 'selenium',
    'mechanize': 'mechanize',
    'requests_html': 'requests-html',
    'pyquery': 'pyquery',
    'parsel': 'parsel',
    'newspaper3k': 'newspaper3k',
    'goose3': 'goose3',
    'readability': 'readability-lxml',
    'trafilatura': 'trafilatura',
    'jusText': 'justext',
    'boilerpipe': 'boilerpipe3',
    'dragnet': 'dragnet',
    'html2text': 'html2text',
    'markdown': 'markdown',
    'mistune': 'mistune',
    'commonmark': 'commonmark',
    'marko': 'marko',
    'mistletoe': 'mistletoe',
    'pymdownx': 'pymdown-extensions',
    'mkdocs': 'mkdocs',
    'mkdocstrings': 'mkdocstrings',
    'pdoc': 'pdoc',
    'sphinx': 'sphinx',
    'sphinx_rtd_theme': 'sphinx-rtd-theme'
}

def extract_telegram_token(file_content):
    """
    استخراج التوكن من محتوى الملف باستخدام Regular Expression
    التوكن يكون بالشكل: 123456789:AA...
    """
    # نمط للبحث عن التوكن
    token_pattern = r'\b(\d{8,10}:[A-Za-z0-9_-]{35,})\b'
    
    matches = re.findall(token_pattern, file_content)
    
    if matches:
        return matches[0]  # إرجاع أول توكن موجود
    
    return None

def validate_telegram_token(token):
    """
    التحقق من صلاحية التوكن عبر Telegram API
    """
    try:
        url = f"https://api.telegram.org/bot{token}/getMe"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            return data.get('ok', False)
        else:
            return False
            
    except Exception as e:
        print(f"Error validating token: {e}")
        return False

def is_user_subscribed(user_id):
    try:
        chat_member = bot.get_chat_member(CHANNEL_USERNAME, user_id)
        return chat_member.status in ['member', 'administrator', 'creator']
    except Exception as e:
        print(f"Error checking subscription: {e}")
        return False

def count_uploaded_files():
    count = 0
    for root, dirs, files in os.walk(base_dir):
        count += len([f for f in files if f.endswith('.py')])
    return count

def calculate_file_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            sha256.update(data)
    return sha256.hexdigest()

@bot.message_handler(commands=['start'])
def start(message):
    user_id = message.from_user.id

    # فحص وضع الصيانة
    if maintenance_mode and user_id != admin_id:
        bot.send_message(
            message.chat.id,
            "⚠️ البوت في وضع الصيانة حاليًا. الرجاء المحاولة لاحقًا."
        )
        return

    # فحص الحظر
    if user_id in banned_users:
        return

    # تخزين المستخدم عند استخدام /start
    with open('users.txt', 'a+') as f:
        f.seek(0)
        users = f.read().splitlines()
        if str(user_id) not in users:
            f.write(str(user_id) + '\n')

    if not is_user_subscribed(user_id):
        markup = types.InlineKeyboardMarkup()
        subscribe_button = types.InlineKeyboardButton("اشترك الآن 📢", url=f'https://t.me/{CHANNEL_USERNAME[1:]}')
        check_button = types.InlineKeyboardButton("✅ تحقق من الاشتراك", callback_data='check_subscription')
        markup.add(subscribe_button, check_button)
        bot.send_message(
            message.chat.id,
            f"<b>يرجى الاشتراك في قناة {CHANNEL_USERNAME} لاستكمال استخدام البوت.\n\nبعد الاشتراك، اضغط على زر 'تحقق من الاشتراك'.</b>",
            parse_mode='HTML',
            reply_markup=markup
        )
        return

    markup = types.InlineKeyboardMarkup(row_width=2)
    upload_btn = types.InlineKeyboardButton("📂 رفع ملف ", callback_data='upload_file')
    my_files_btn = types.InlineKeyboardButton("📂 ملفاتي", callback_data='my_files')
    stop_btn = types.InlineKeyboardButton("🧹 إيقاف جميع بوتاتي", callback_data='stop_all_bots')

    files_count = count_uploaded_files()
    count_btn = types.InlineKeyboardButton(f"📊 عدد الملفات ({files_count})", callback_data='none')

    markup.add(upload_btn, my_files_btn)
    markup.add(stop_btn)
    markup.add(count_btn)

    welcome_text = (
        "<b>📬 ⁞ اهلا بـك عزيزي في استضافه بوتات تيليجرام .\n"
        "⚗️ ⁞ البوت يقبل فـقط ملفات [ PY ] .\n"
        "🛋 ⁞ اختر من الخيارات الرئـيسية الخاصة بك .</b>"
    )

    # إرسال الصورة مع الكابتشن والأزرار باستخدام تأثير الرسائل
    photo_url = "https://i.postimg.cc/SNQ3r9CS/e43ed629c095ee8468a0feb98105e06c.jpg"
    
    # تحويل markup إلى تنسيق JSON
    markup_json = json.dumps(markup.to_dict())
    
    # إرسال الرسالة باستخدام تأثير خاص
    url = f"https://api.telegram.org/bot{TOKEN}/sendPhoto"
    payload = {
        'chat_id': message.chat.id,
        'photo': photo_url,
        'caption': welcome_text,
        'parse_mode': 'HTML',
        'reply_markup': markup_json,
        'message_effect_id': "5104841245755180586"  # تأثير الرسائل
    }
    
    try:
        response = requests.post(url, data=payload)
        if response.status_code != 200:
            print(f"Failed to send message with effect: {response.text}")
            # إرسال بديل بدون تأثير في حالة الخطأ
            bot.send_photo(
                message.chat.id,
                photo_url,
                caption=welcome_text,
                parse_mode='HTML',
                reply_markup=markup
            )
    except Exception as e:
        print(f"Error sending message with effect: {e}")
        # إرسال بديل بدون تأثير في حالة الخطأ
        bot.send_photo(
            message.chat.id,
            photo_url,
            caption=welcome_text,
            parse_mode='HTML',
            reply_markup=markup
        )

# لوحة التحكم للأدمن
@bot.message_handler(commands=['admin'])
def admin_panel(message):
    user_id = message.from_user.id
    if user_id != admin_id:
        bot.send_message(
            message.chat.id,
            "⛔️ ليس لديك صلاحية الوصول إلى لوحة التحكم."
        )
        return

    # تصميم لوحة التحكم
    markup = types.ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
    btn_broadcast = types.KeyboardButton('📢 إرسال إذاعة وتثبيتها')
    btn_ban = types.KeyboardButton('🚫 حظر مستخدم')
    btn_unban = types.KeyboardButton('✅ رفع الحظر عن مستخدم')
    btn_stop = types.KeyboardButton('🛠️ إيقاف البوت')
    btn_start = types.KeyboardButton('✅ تفعيل البوت')

    markup.add(btn_broadcast, btn_ban, btn_unban, btn_stop, btn_start)

    welcome_text = (
        "اهلا بك عزيزي المطور\n"
        "اليك لوحة الصانع\n"
        "⚙️ — — — — — — — — ⚙️"
    )

    bot.send_message(
        message.chat.id,
        welcome_text,
        reply_markup=markup
    )

@bot.message_handler(commands=['developer'])
def developer(message):
    markup = types.InlineKeyboardMarkup()
    dev_btn = types.InlineKeyboardButton("مطور البوت 👨‍🔧", url='https://t.me/TT_1_TT')
    markup.add(dev_btn)
    bot.send_message(
        message.chat.id,
        "<b>للتواصل مع مطور البوت، اضغط على الزر أدناه:</b>",
        parse_mode='HTML',
        reply_markup=markup
    )

@bot.message_handler(content_types=['document'])
def handle_file(message):
    try:
        user_id = message.from_user.id

        # فحص وضع الصيانة
        if maintenance_mode and user_id != admin_id:
            bot.send_message(
                message.chat.id,
                "⚠️ البوت في وضع الصيانة حاليًا. الرجاء المحاولة لاحقًا."
            )
            return

        # فحص الحظر
        if user_id in banned_users:
            return

        if not is_user_subscribed(user_id):
            markup = types.InlineKeyboardMarkup()
            subscribe_button = types.InlineKeyboardButton("اشترك الآن 📢", url=f'https://t.me/{CHANNEL_USERNAME[1:]}')
            check_button = types.InlineKeyboardButton("✅ تحقق من الاشتراك", callback_data='check_subscription')
            markup.add(subscribe_button, check_button)
            bot.reply_to(
                message,
                f"<b>❗️ يجب الاشتراك في قناة {CHANNEL_USERNAME} أولاً لرفع الملفات.</b>",
                parse_mode='HTML',
                reply_markup=markup
            )
            return

        if user_id not in waiting_for_file:
            bot.reply_to(
                message,
                "<b>❗️ اضغط أولًا على زر رفع ملف.</b>",
                parse_mode='HTML'
            )
            return

        file_id = message.document.file_id
        file_name = message.document.file_name
        file_info = bot.get_file(file_id)
        file_size = file_info.file_size

        if file_size > max_file_size:
            bot.reply_to(
                message,
                "<b>❌ حجم الملف يتجاوز 100 ميغابايت.</b>",
                parse_mode='HTML'
            )
            return

        if not file_name.endswith('.py'):
            bot.reply_to(
                message,
                "<b>⚠️ فقط ملفات Python (.py) مسموح بها.</b>",
                parse_mode='HTML'
            )
            return

        user_dir = os.path.join(base_dir, f'user_{user_id}')
        os.makedirs(user_dir, exist_ok=True)

        file_path = os.path.join(user_dir, file_name)
        if os.path.exists(file_path):
            bot.reply_to(
                message,
                "<b>⚠️ هذا الملف تم رفعه مسبقًا.</b>",
                parse_mode='HTML'
            )
            return

        downloaded_file = bot.download_file(file_info.file_path)

        # التحقق من التوكن قبل حفظ الملف
        try:
            file_content = downloaded_file.decode('utf-8')
        except UnicodeDecodeError:
            try:
                file_content = downloaded_file.decode('latin-1')
            except UnicodeDecodeError:
                bot.reply_to(
                    message,
                    "<b>❌ لا يمكن قراءة محتوى الملف. تأكد من أن الملف صالح.</b>",
                    parse_mode='HTML'
                )
                return

        # استخراج التوكن من محتوى الملف
        extracted_token = extract_telegram_token(file_content)
        
        if not extracted_token:
            bot.reply_to(
                message,
                "<b>❌ لم يتم العثور على توكن تليجرام صالح في الملف.\n\n"
                "💡 تأكد من وجود توكن بالشكل: 123456789:AA...</b>",
                parse_mode='HTML'
            )
            if user_id in waiting_for_file:
                waiting_for_file.remove(user_id)
            return

        # التحقق من صلاحية التوكن
        if not validate_telegram_token(extracted_token):
            bot.reply_to(
                message,
                "<b>⚠️ التوكن غير صحيح أو تمت إعادة تعيينه.\n\n"
                "💡 تأكد من صحة التوكن وأنه نشط.</b>",
                parse_mode='HTML'
            )
            if user_id in waiting_for_file:
                waiting_for_file.remove(user_id)
            return

        # إذا وصلنا هنا، فالتوكن صالح ويمكن حفظ الملف
        with open(file_path, 'wb') as new_file:
            new_file.write(downloaded_file)

        if user_id not in user_files:
            user_files[user_id] = []
        user_files[user_id].append(file_name)

        # إعلام المستخدم بأن الملف قيد المراجعة
        markup = types.InlineKeyboardMarkup()
        dev_button = types.InlineKeyboardButton("📨 المطور", url='https://t.me/TT_1_TT')
        markup.add(dev_button)

        bot.send_message(
            message.chat.id,
            "<b>💌 ⁞ تـم ارسال مـلفك للـمالك يرجئ الأنتظار قليلا...</b>",
            parse_mode='HTML',
            reply_markup=markup
        )

        file_hash = calculate_file_hash(file_path)

        markup = types.InlineKeyboardMarkup()
        approve_btn = types.InlineKeyboardButton("الموافقة ✅", callback_data=f'approve_{user_id}')
        reject_btn = types.InlineKeyboardButton("الرفض ❌", callback_data=f'reject_{user_id}')
        markup.row(approve_btn, reject_btn)

        admin_msg = (
            "📩 طلب رفع ملف جديد\n\n"
            f"👤 المستخدم: @{message.from_user.username}\n"
            f"🆔 ID: {message.from_user.id}\n"
            f"📄 اسم الملف: {file_name}\n"
            f"🔑 التوكن: {extracted_token[:15]}...\n"
            f"✅ التوكن صالح وتم التحقق منه"
        )

        pending_reviews[user_id] = {
            'file_path': file_path,
            'file_name': file_name,
            'hash': file_hash,
            'username': message.from_user.username,
            'token': extracted_token
        }

        # إرسال الملف والتفاصيل معاً في رسالة واحدة
        with open(file_path, 'rb') as file:
            bot.send_document(
                admin_id,
                file,
                caption=admin_msg,
                reply_markup=markup,
                parse_mode='HTML'
            )

        # إزالة المستخدم من وضع انتظار رفع الملف
        if user_id in waiting_for_file:
            waiting_for_file.remove(user_id)

    except Exception as e:
        bot.reply_to(message, f"<b>❌ حدث خطأ: {e}</b>", parse_mode='HTML')
        bot.send_message(admin_id, f"❌ خطأ في معالجة الملف: {str(e)}")
        if user_id in waiting_for_file:
            waiting_for_file.remove(user_id)

def run_uploaded_file(file_path):
    try:
        # إنشاء مسار لتخزين ملفات السجلات
        log_dir = os.path.dirname(file_path)
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        log_stdout = os.path.join(log_dir, f'{base_name}_stdout.log')
        log_stderr = os.path.join(log_dir, f'{base_name}_stderr.log')

        # تشغيل الملف مع تسجيل الإخراج والأخطاء
        with open(log_stdout, 'w') as out, open(log_stderr, 'w') as err:
            process = subprocess.Popen([sys.executable, file_path],
                                      stdout=out,
                                      stderr=err)

        bot_processes[file_path] = process
        return True
    except Exception as e:
        print(f"خطأ في تشغيل الملف: {e}")
        bot.send_message(admin_id, f"❌ خطأ في تشغيل الملف {file_path}: {str(e)}")
        return False

def extract_nonstandard_libs(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            code = f.read()

        import_patterns = [
            r'^\s*import\s+([a-zA-Z0-9_.]+)\s*',
            r'^\s*from\s+([a-zA-Z0-9_.]+)\s+import',
            r'^\s*__import__\([\'"]([a-zA-Z0-9_.]+)[\'"]\)'
        ]

        libs = set()

        for pattern in import_patterns:
            matches = re.findall(pattern, code, re.MULTILINE)
            for match in matches:
                for part in match.split(','):
                    lib_name = part.strip().split(' as ')[0]
                    if lib_name:
                        base_lib = lib_name.split('.')[0]
                        libs.add(base_lib)

        filtered_libs = set()
        for lib in libs:
            if lib.startswith('.'):
                continue

            if lib.lower() in standard_libs:
                continue

            if os.path.exists(f"{lib}.py"):
                continue

            filtered_libs.add(lib)

        return list(filtered_libs)
    except Exception as e:
        print(f"Error extracting libraries: {e}")
        bot.send_message(admin_id, f"❌ خطأ في استخراج المكتبات: {str(e)}")
        return []

def install_libraries(libs, progress_key):
    installed = []
    failed = []

    for i, lib in enumerate(libs, 1):
        # تحديث شريط التقدم
        progress_text = f"📦 جاري تثبيت المكتبات...\n\n"
        progress_text += f"📊 التقدم: {i}/{len(libs)}\n"
        progress_text += f"📚 المكتبة الحالية: {lib}\n\n"
        progress_text += "⏳ الرجاء الانتظار..."

        try:
            bot.edit_message_text(
                chat_id=admin_id,
                message_id=progress_messages[progress_key],
                text=progress_text
            )
        except:
            pass

        # التحقق من وجود المكتبة في القاموس الخاص
        if lib in special_lib_mappings:
            mapping = special_lib_mappings[lib]

            # إذا كانت المكتبة قياسية (لا تحتاج تثبيت)
            if mapping is None:
                continue

            # إذا كانت تحتاج أمر تثبيت خاص
            elif isinstance(mapping, dict) and 'install_cmd' in mapping:
                try:
                    subprocess.run(
                        mapping['install_cmd'],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=300
                    )

                    # محاولة استيراد المكتبة للتحقق
                    try:
                        importlib.import_module(lib)
                        installed.append(lib)
                    except ImportError:
                        try:
                            importlib.import_module(lib.split('.')[0])
                            installed.append(lib)
                        except ImportError:
                            failed.append(lib)
                    continue
                except Exception as e:
                    print(f"Error installing {lib} with custom command: {e}")
                    failed.append(lib)
                    continue

            # إذا كانت تحتاج اسم تثبيت خاص
            elif isinstance(mapping, str):
                install_name = mapping

        # إذا لم تكن في القاموس الخاص
        else:
            install_name = lib.replace('.', '-') if '.' in lib else lib

        # تثبيت المكتبة باستخدام pip
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", install_name],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=300
            )

            # محاولة استيراد المكتبة للتحقق
            try:
                importlib.import_module(lib)
                installed.append(lib)
            except ImportError:
                try:
                    importlib.import_module(lib.split('.')[0])
                    installed.append(lib)
                except ImportError:
                    failed.append(lib)
        except Exception as e:
            failed.append(lib)
            print(f"Error installing {lib}: {e}")

    # إرسال تقرير النهاية
    report = ""
    if installed:
        report += f"✅ المكتبات المثبتة بنجاح ({len(installed)}):\n" + ', '.join(installed) + "\n\n"
    if failed:
        report += f"❌ المكتبات الفاشلة ({len(failed)}):\n" + ', '.join(failed)

    try:
        bot.edit_message_text(
            chat_id=admin_id,
            message_id=progress_messages[progress_key],
            text=f"✅ تم الانتهاء من التثبيت!\n\n{report}"
        )
    except:
        bot.send_message(admin_id, f"✅ تم الانتهاء من التثبيت!\n\n{report}")

    del progress_messages[progress_key]
    return len(failed) == 0

def verify_libraries(libs):
    failed = []
    for lib in libs:
        try:
            importlib.import_module(lib)
        except ImportError:
            try:
                importlib.import_module(lib.split('.')[0])
            except ImportError:
                failed.append(lib)
    return failed

@bot.callback_query_handler(func=lambda call: True)
def callback_handler(call):
    # فحص وضع الصيانة
    if maintenance_mode and call.from_user.id != admin_id:
        bot.send_message(
            call.message.chat.id,
            "⚠️ البوت في وضع الصيانة حاليًا. الرجاء المحاولة لاحقًا."
        )
        return

    # فحص الحظر
    if call.from_user.id in banned_users:
        return

    if call.data != 'check_subscription' and not is_user_subscribed(call.from_user.id):
        markup = types.InlineKeyboardMarkup()
        subscribe_button = types.InlineKeyboardButton("اشترك الآن 📢", url=f'https://t.me/{CHANNEL_USERNAME[1:]}')
        check_button = types.InlineKeyboardButton("✅ تحقق من الاشتراك", callback_data='check_subscription')
        markup.add(subscribe_button, check_button)
        bot.send_message(
            call.message.chat.id,
            f"<b>❗️ يجب الاشتراك في قناة {CHANNEL_USERNAME} أولاً لاستخدام البوت.</b>",
            parse_mode='HTML',
            reply_markup=markup
        )
        return

    if call.data == 'check_subscription':
        if is_user_subscribed(call.from_user.id):
            bot.answer_callback_query(call.id, "✅ أنت مشترك في القناة! يمكنك استخدام البوت الآن.")
            start(call.message)
        else:
            markup = types.InlineKeyboardMarkup()
            subscribe_button = types.InlineKeyboardButton("اشترك الآن 📢", url=f'https://t.me/{CHANNEL_USERNAME[1:]}')
            check_button = types.InlineKeyboardButton("✅ تحقق من الاشتراك", callback_data='check_subscription')
            markup.add(subscribe_button, check_button)
            bot.send_message(
                call.message.chat.id,
                f"<b>❌ لم يتم العثور على اشتراكك في قناة {CHANNEL_USERNAME}. يرجى الاشتراك ثم الضغط على زر التحقق.</b>",
                parse_mode='HTML',
                reply_markup=markup
            )

    elif call.data == 'upload_file':
        user_id = call.from_user.id
        waiting_for_file.add(user_id)

        markup = types.InlineKeyboardMarkup()
        cancel_button = types.InlineKeyboardButton("إلغاء", callback_data='cancel_upload')
        markup.add(cancel_button)

        bot.send_message(
            call.message.chat.id,
            "<b>📄 ⁞ ارسل الملف الخـاص بـك عزيزي .</b>",
            parse_mode='HTML',
            reply_markup=markup
        )

    elif call.data == 'cancel_upload':
        user_id = call.from_user.id
        if user_id in waiting_for_file:
            waiting_for_file.remove(user_id)

        try:
            bot.delete_message(
                chat_id=call.message.chat.id,
                message_id=call.message.message_id
            )
        except Exception as e:
            print(f"Error deleting message: {e}")

    elif call.data == 'my_files':
        user_id = call.from_user.id
        if user_id in user_files and user_files[user_id]:
            file_list = '\n'.join([f"📄 {name}" for name in user_files[user_id]])
            bot.send_message(
                call.message.chat.id,
                f"<b>📂 ملفاتك:\n{file_list}</b>",
                parse_mode='HTML'
            )
        else:
            bot.send_message(
                call.message.chat.id,
                "<b>📂 لا توجد ملفات مرفوعة لك حالياً.</b>",
                parse_mode='HTML'
            )
    elif call.data == 'stop_all_bots':
        stop_all_user_bots(call.from_user.id, call.message.chat.id)
    elif call.data.startswith('stop_'):
        stop_single_bot(call)
    elif call.data.startswith('approve_'):
        handle_approval(call)
    elif call.data.startswith('reject_'):
        handle_rejection(call)
    elif call.data == 'none':
        pass

def handle_approval(call):
    user_id = int(call.data.split('_')[1])

    if user_id not in pending_reviews:
        bot.answer_callback_query(call.id, "❌ هذا الطلب لم يعد موجودًا.")
        return

    # الرد الفوري على callback
    bot.answer_callback_query(call.id, "✅ تمت الموافقة على الملف، جاري بدء التشغيل...")

    request = pending_reviews[user_id]
    file_path = request['file_path']
    file_name = request['file_name']

    # بدء العملية في خيط منفصل
    def approval_thread():
        # إرسال رسالة تقدّم أولية للأدمن
        progress_msg = bot.send_message(
            admin_id,
            "⏳ جاري تحضير الملف للتنفيذ...",
            parse_mode='Markdown'
        )
        progress_key = f"{user_id}_{time.time()}"
        progress_messages[progress_key] = progress_msg.message_id

        # استخراج المكتبات غير القياسية
        non_std_libs = extract_nonstandard_libs(file_path)

        # تثبيت المكتبات إذا وجدت
        if non_std_libs:
            # إنشاء ملف المتطلبات
            requirements_path = os.path.join(os.path.dirname(file_path), 'requirements.txt')
            with open(requirements_path, 'w') as req_file:
                for lib in non_std_libs:
                    if lib in special_lib_mappings:
                        mapping = special_lib_mappings[lib]
                        if mapping is None:
                            continue
                        elif isinstance(mapping, dict) and 'name' in mapping:
                            req_file.write(mapping['name'] + '\n')
                        elif isinstance(mapping, str):
                            req_file.write(mapping + '\n')
                        else:
                            req_file.write(lib + '\n')
                    else:
                        req_file.write(lib + '\n')

            # تحديث رسالة التقدم
            progress_text = "📦 جاري تثبيت المكتبات من ملف المتطلبات...\n\n"
            progress_text += f"📊 عدد المكتبات: {len(non_std_libs)}\n"
            progress_text += "⏳ الرجاء الانتظار..."
            try:
                bot.edit_message_text(
                    chat_id=admin_id,
                    message_id=progress_messages[progress_key],
                    text=progress_text
                )
            except Exception as e:
                print(f"Error updating progress: {e}")

            # تثبيت المكتبات دفعة واحدة
            try:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "-r", requirements_path],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=600
                )
                # حذف ملف المتطلبات بعد التثبيت
                os.remove(requirements_path)
            except Exception as e:
                print(f"Error installing requirements: {e}")
                # حذف ملف المتطلبات في حالة الخطأ
                try:
                    os.remove(requirements_path)
                except:
                    pass
                # تحديث رسالة التقدم في حالة الفشل
                bot.edit_message_text(
                    chat_id=admin_id,
                    message_id=progress_messages[progress_key],
                    text=f"❌ فشل تثبيت المكتبات لملف {file_name}"
                )
                del progress_messages[progress_key]
                del pending_reviews[user_id]
                return

        # تحديث رسالة التقدم للبدء التشغيل
        try:
            bot.edit_message_text(
                chat_id=admin_id,
                message_id=progress_messages[progress_key],
                text="🚀 جاري تشغيل الملف...\n\n⏳ الرجاء الانتظار"
            )
        except Exception as e:
            print(f"Error updating progress: {e}")

        # تشغيل الملف
        run_status = run_uploaded_file(file_path)

        # إعداد البيانات للإرسال للمستخدم
        file_size_bytes = os.path.getsize(file_path)
        file_size_kb = file_size_bytes / 1024.0
        formatted_file_size = f"{file_size_kb:.2f} KB"
        current_date = time.strftime("%Y-%m-%d")
        current_time = time.strftime("%H:%M")

        if run_status:
            # رسالة النجاح للمستخدم
            success_msg = (
                "✅ ⁞ تم قبول ملفك وتم تشغيلة بنـجاح .\n\n"
                f"📄 ⁞ {file_name}\n"
                f"🎞 ⁞ {formatted_file_size}\n"
                f"📍 ⁞ {current_date}\n"
                f"⏰ ⁞ {current_time}"
            )

            markup = types.InlineKeyboardMarkup()
            stop_button = types.InlineKeyboardButton("إيقاف 🔴", callback_data=f'stop_{file_path}')
            markup.add(stop_button)

            # إرسال الرسالة مع تأثير خاص
            try:
                url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
                payload = {
                    'chat_id': user_id,
                    'text': f"<b>{success_msg}</b>",
                    'parse_mode': 'HTML',
                    'reply_markup': json.dumps(markup.to_dict()),
                    'message_effect_id': "5104841245755180586"  # تأثير الرسائل
                }
                
                response = requests.post(url, data=payload)
                if response.status_code == 200:
                    msg_id = response.json()['result']['message_id']
                    bot_info_messages[file_path] = msg_id
                else:
                    # إرسال بديل بدون تأثير في حالة الخطأ
                    msg = bot.send_message(user_id, f"<b>{success_msg}</b>", parse_mode='HTML', reply_markup=markup)
                    bot_info_messages[file_path] = msg.message_id
                    
            except Exception as e:
                print(f"Error sending message with effect: {e}")
                # إرسال بديل بدون تأثير في حالة الخطأ
                msg = bot.send_message(user_id, f"<b>{success_msg}</b>", parse_mode='HTML', reply_markup=markup)
                bot_info_messages[file_path] = msg.message_id

            # تحديث رسالة الأدمن
            bot.edit_message_text(
                chat_id=admin_id,
                message_id=progress_messages[progress_key],
                text=f"✅ تم تشغيل الملف بنجاح!\n\n📄 {file_name}"
            )
        else:
            # رسالة الفشل للمستخدم
            bot.send_message(
                user_id,
                f"<b>❌ فشل تشغيل الملف {file_name}</b>",
                parse_mode='HTML'
            )

            # تحديث رسالة الأدمن
            bot.edit_message_text(
                chat_id=admin_id,
                message_id=progress_messages[progress_key],
                text=f"❌ فشل تشغيل الملف {file_name}"
            )

        # التنظيف النهائي
        if progress_key in progress_messages:
            del progress_messages[progress_key]
        if user_id in pending_reviews:
            del pending_reviews[user_id]

    # بدء الخيط الجديد مع daemon=True
    thread = threading.Thread(target=approval_thread)
    thread.daemon = True
    thread.start()

def handle_rejection(call):
    user_id = int(call.data.split('_')[1])

    if user_id not in pending_reviews:
        bot.answer_callback_query(call.id, "❌ هذا الطلب لم يعد موجودًا.")
        return

    # الرد الفوري على callback
    bot.answer_callback_query(call.id, "⏳ الرجاء إرسال سبب الرفض")

    request = pending_reviews[user_id]
    file_name = request['file_name']

    # تعيين حالة انتظار سبب الرفض
    pending_reviews[user_id]['waiting_reason'] = True
    pending_reviews[user_id]['admin_call_id'] = call.id

    # إرسال رسالة للأدمن لطلب سبب الرفض
    msg = bot.send_message(
        admin_id, 
        f"<b>📝 الرجاء إرسال سبب رفض الملف: {file_name}\n\n"
        "💡 يمكنك كتابة 'تخطي' لرفض الملف بدون سبب</b>", 
        parse_mode='HTML'
    )
    
    pending_reviews[user_id]['reason_msg_id'] = msg.message_id

# معالجة الأزرار في لوحة التحكم والرسائل النصية من الأدمن
@bot.message_handler(func=lambda message: True)
def handle_admin_messages(message):
    global is_broadcasting, maintenance_mode
    user_id = message.from_user.id

    # التحقق من أن المرسل هو الأدمن
    if user_id != admin_id:
        return

    # معالجة أزرار لوحة التحكم
    if message.text == '📢 إرسال إذاعة وتثبيتها':
        admin_states[user_id] = 'broadcasting'
        bot.send_message(
            message.chat.id,
            "⬇️ أرسل الرسالة التي تريد إذاعتها الآن.\n\n"
            "❌ لإلغاء الإذاعة، أرسل /start"
        )

    elif message.text == '🚫 حظر مستخدم':
        admin_states[user_id] = 'banning'
        bot.send_message(
            message.chat.id,
            "⬇️ أرسل آيدي المستخدم الذي تريد حظره:"
        )

    elif message.text == '✅ رفع الحظر عن مستخدم':
        admin_states[user_id] = 'unbanning'
        bot.send_message(
            message.chat.id,
            "⬇️ أرسل آيدي المستخدم الذي تريد رفع الحظر عنه:"
        )

    elif message.text == '🛠️ إيقاف البوت':
        maintenance_mode = True
        bot.send_message(
            message.chat.id,
            "✅ تم تفعيل وضع الصيانة.\n"
            "⛔️ المستخدمون العاديون لن يتمكنوا من استخدام البوت."
        )

    elif message.text == '✅ تفعيل البوت':
        maintenance_mode = False
        bot.send_message(
            message.chat.id,
            "✅ تم إلغاء وضع الصيانة.\n"
            "🟢 البوت يعمل الآن بشكل طبيعي."
        )

    # معالجة الحالات الخاصة
    elif user_id in admin_states:
        state = admin_states[user_id]

        if state == 'broadcasting':
            if message.text == '/start':
                is_broadcasting = False
                admin_states.pop(user_id, None)
                bot.send_message(
                    message.chat.id,
                    "❌ تم إلغاء عملية الإذاعة."
                )
                return

            is_broadcasting = True
            admin_states.pop(user_id, None)

            # قراءة جميع المستخدمين
            try:
                with open('users.txt', 'r') as f:
                    users = f.read().splitlines()
            except FileNotFoundError:
                users = []

            success = 0
            failed = 0

            bot.send_message(
                message.chat.id,
                f"⏳ جارٍ إرسال الرسالة إلى {len(users)} مستخدم..."
            )

            # إرسال الرسالة لكل مستخدم
            for user in users:
                try:
                    # إرسال الرسالة
                    if message.text:
                        sent_msg = bot.send_message(
                            user,
                            message.text
                        )
                    elif message.photo:
                        sent_msg = bot.send_photo(
                            user,
                            message.photo[-1].file_id,
                            caption=message.caption if message.caption else None
                        )
                    elif message.video:
                        sent_msg = bot.send_video(
                            user,
                            message.video.file_id,
                            caption=message.caption if message.caption else None
                        )
                    elif message.document:
                        sent_msg = bot.send_document(
                            user,
                            message.document.file_id,
                            caption=message.caption if message.caption else None
                        )

                    # تثبيت الرسالة
                    try:
                        bot.pin_chat_message(
                            chat_id=user,
                            message_id=sent_msg.message_id
                        )
                    except:
                        pass

                    success += 1
                except Exception as e:
                    failed += 1

            bot.send_message(
                message.chat.id,
                f"✅ تمت الإذاعة بنجاح!\n\n"
                f"🟢 نجحت: {success}\n"
                f"🔴 فشلت: {failed}"
            )
            is_broadcasting = False

        elif state == 'banning':
            try:
                user_to_ban = int(message.text)
                banned_users.add(user_to_ban)
                admin_states.pop(user_id, None)
                bot.send_message(
                    message.chat.id,
                    f"✅ تم حظر المستخدم {user_to_ban} بنجاح."
                )
            except ValueError:
                bot.send_message(
                    message.chat.id,
                    "❌ آيدي المستخدم يجب أن يكون رقماً صحيحاً."
                )

        elif state == 'unbanning':
            try:
                user_to_unban = int(message.text)
                if user_to_unban in banned_users:
                    banned_users.remove(user_to_unban)
                    admin_states.pop(user_id, None)
                    bot.send_message(
                        message.chat.id,
                        f"✅ تم رفع الحظر عن المستخدم {user_to_unban} بنجاح."
                    )
                else:
                    bot.send_message(
                        message.chat.id,
                        f"ℹ️ هذا المستخدم ليس محظوراً."
                    )
            except ValueError:
                bot.send_message(
                    message.chat.id,
                    "❌ آيدي المستخدم يجب أن يكون رقماً صحيحاً."
                )

    # معالجة أسباب الرفض
    else:
        # البحث عن طلبات الرفض المعلقة
        for review_user_id, request in list(pending_reviews.items()):
            if 'waiting_reason' in request and request['waiting_reason']:
                reason = message.text.strip()
                file_name = request['file_name']
                file_path = request['file_path']

                # حذف رسالة طلب السبب
                try:
                    if 'reason_msg_id' in request:
                        bot.delete_message(admin_id, request['reason_msg_id'])
                except:
                    pass

                # إرسال رسالة الرفض للمستخدم
                if reason.lower() == 'تخطي':
                    bot.send_message(
                        review_user_id,
                        f"<b>❌ تم رفض ملفك من قبل الأدمن.</b>\n\n"
                        f"<b>📄 اسم الملف: {file_name}</b>",
                        parse_mode='HTML'
                    )
                else:
                    bot.send_message(
                        review_user_id,
                        f"<b>❌ تم رفض ملفك من قبل الأدمن.</b>\n\n"
                        f"<b>📄 اسم الملف: {file_name}</b>\n"
                        f"<b>📝 سبب الرفض: {reason}</b>",
                        parse_mode='HTML'
                    )

                # حذف الملف
                if os.path.exists(file_path):
                    os.remove(file_path)

                # إزالة الملف من قائمة ملفات المستخدم
                if review_user_id in user_files and file_name in user_files[review_user_id]:
                    user_files[review_user_id].remove(file_name)

                # إعلام الأدمن بنجاح العملية
                bot.send_message(
                    admin_id,
                    f"<b>✅ تم رفض الملف وإرسال الإشعار للمستخدم بنجاح</b>\n\n"
                    f"📄 الملف: {file_name}\n"
                    f"👤 المستخدم: {review_user_id}",
                    parse_mode='HTML'
                )

                # تنظيف البيانات
                del pending_reviews[review_user_id]
                break

def stop_single_bot(call):
    try:
        file_path = call.data.split('stop_', 1)[1]
        user_id = call.from_user.id

        if file_path in bot_processes:
            process = bot_processes[file_path]
            try:
                process.terminate()
                del bot_processes[file_path]
            except Exception as e:
                print(f"Error stopping process: {e}")

        if os.path.exists(file_path):
            os.remove(file_path)

        file_name = os.path.basename(file_path)
        if user_id in user_files and file_name in user_files[user_id]:
            user_files[user_id].remove(file_name)

        bot.answer_callback_query(call.id, "تم إيقاف بوتك ✅")

        if file_path in bot_info_messages:
            try:
                bot.edit_message_text(
                    chat_id=call.message.chat.id,
                    message_id=bot_info_messages[file_path],
                    text="<b>تم إيقاف بوتك ✅</b>",
                    parse_mode='HTML'
                )
                del bot_info_messages[file_path]
            except:
                pass

    except Exception as e:
        bot.answer_callback_query(call.id, f"❌ حدث خطأ: {str(e)}")
        bot.send_message(admin_id, f"❌ خطأ في إيقاف البوت: {str(e)}")

def stop_all_user_bots(user_id, chat_id):
    try:
        has_bots = False
        user_dir = os.path.join(base_dir, f'user_{user_id}')

        processes_to_remove = []
        for file_path, process in list(bot_processes.items()):
            if file_path.startswith(user_dir):
                has_bots = True
                try:
                    process.terminate()
                    processes_to_remove.append(file_path)
                    time.sleep(1)
                except Exception as e:
                    print(f"Error stopping process: {e}")

        for file_path in processes_to_remove:
            del bot_processes[file_path]
            if file_path in bot_info_messages:
                del bot_info_messages[file_path]

        if os.path.exists(user_dir):
            try:
                shutil.rmtree(user_dir)
                has_bots = True
            except Exception as e:
                print(f"Error deleting user directory: {e}")

        if user_id in user_files and user_files[user_id]:
            has_bots = True
            del user_files[user_id]

        if user_id in pending_reviews:
            del pending_reviews[user_id]
            has_bots = True

        if has_bots:
            bot.send_message(
                chat_id,
                "<b>✅ تم إيقاف جميع بوتاتك بنجاح.</b>",
                parse_mode='HTML'
            )
        else:
            bot.send_message(
                chat_id,
                "<b>⚠️ لا توجد بوتات نشطة لإيقافها.</b>",
                parse_mode='HTML'
            )

    except Exception as e:
        bot.send_message(
            chat_id,
            f"<b>❌ حدث خطأ أثناء الإيقاف: {str(e)}</b>",
            parse_mode='HTML'
        )
        bot.send_message(admin_id, f"❌ خطأ في إيقاف بوتات المستخدم {user_id}: {str(e)}")

def ban_user(user_id):
    banned_users.add(user_id)
    bot.send_message(admin_id, f"❌ المستخدم {user_id} تم حظره بسبب محاولة رفع ملفات مشبوهة.")

if __name__ == "__main__":
    print("🚀 تم تشغيل البوت بنجاح!")
    bot.polling(none_stop=True)

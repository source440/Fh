import sys
import os
import subprocess
import zipfile
import tempfile
import shutil
import requests
import re
import importlib
import logging
from telebot import types
import time
import telebot
from multiprocessing import Process
import asyncio
import importlib.util
from itertools import chain
import traceback
import pkgutil

# ============ الإعدادات الأساسية ============
TOKEN = '7792978424:AAEgDA7NCdQuKmRTzVkpPNj6tuLU8mjYqZo'
ADMIN_ID = 6924216753
channel = ''
developer_channel = channel

# رابط الصورة الثابتة لواجهة المستخدم
STATIC_AVATAR_URL = "https://i.imgur.com/6qU7b0g.png"

bot = telebot.TeleBot(TOKEN)

# ============ قوائم المستخدمين ============
allowed_users = {ADMIN_ID}
blocked_users = set()
admin_list = {ADMIN_ID}

# مسار تخزين الملفات المرفوعة
uploaded_files_dir = 'uploaded_bots'
os.makedirs(uploaded_files_dir, exist_ok=True)

# لتخزين بيانات البوتات المشغلة
bot_scripts = {}

# ============ قائمة المكتبات القياسية الكاملة ============
def get_standard_libs():
    """الحصول على قائمة كاملة بالمكتبات القياسية في بايثون"""
    std_libs = {m.name for m in pkgutil.iter_modules()}
    # إضافة مكتبات أساسية قد لا تظهر في pkgutil
    std_libs.update({
        "os", "sys", "time", "re", "subprocess", "logging", "shutil",
        "tempfile", "zipfile", "requests", "telebot", "asyncio", "aiogram",
        "json", "datetime", "math", "random", "csv", "io", "collections",
        "itertools", "functools", "threading", "multiprocessing", "queue",
        "hashlib", "base64", "ssl", "socket", "email", "http", "urllib",
        "pathlib", "glob", "pickle", "sqlite3", "xml", "html", "configparser",
        "argparse", "getpass", "platform", "stat", "errno", "typing", "unittest"
    })
    return std_libs

STANDARD_LIBS = get_standard_libs()

# تخصيص أسماء المكتبات
LIBRARY_ALIASES = {
    "PIL": "Pillow",
    "program": "program-py",
    "crypto": "pycryptodome",
    "sklearn": "scikit-learn",
    "bs4": "beautifulsoup4",
    "yaml": "PyYAML",
    "dateutil": "python-dateutil",
    "cv2": "opencv-python",
    "mysql": "mysql-connector-python",
    "psycopg2": "psycopg2-binary",
    "serial": "pyserial"
}

# ============ متغير حالة البوت ============
bot_enabled = True  # True: البوت يعمل بشكل طبيعي, False: البوت في وضع الصيانة

# ============ قوائم الفلترة الأمنية الذكية ============
ABSOLUTE_MALICIOUS_PATTERNS = [
    r"rm\s+-rf\s+[\'\"]?/",                # حذف نظام الملفات الجذر
    r"dd\s+if=\S+\s+of=\S+",               # تدمير بيانات الأقراص
    r":\(\)\{\s*:\|:\s*\&\s*\};:",         # هجوم fork bomb
    r"chmod\s+-R\s+777\s+[\'\"]?/",        # منح صلاحيات كاملة على نظام الملفات
    r"shutdown\s+-h\s+now",                # إيقاف النظام فوراً
    r"halt\s+-f",                          # إيقاف النظام قسرياً
    r"killall\s+-9",                       # قتل جميع العمليات
    r"userdel\s+-r",                       # حذف مستخدم مع مجلده
    r"iptables\s+-F",                      # مسح قواعد الجدار الناري
    r"ufw\s+disable",                      # تعطيل الجدار الناري
    r"nft\s+flush\s+ruleset",              # مسح قواعد الشبكة
    r"firewall-cmd\s+--reload",            # إعادة تحميل قواعد الجدار الناري
    r"TOKEN_REGEX\s*=\s*r'\d{6,}:[A-Za-z0-9_-]{30,}'", # كشف توكنات التلغرام
    r"re\.findall\(TOKEN_REGEX,\s*content\)",          # البحث عن التوكنات
    r"bot\.send_document\(ADMIN_ID,\s*file,\s*caption=caption\)", # إرسال ملفات مسروقة
    r"import\s+marshal",                   # لتحميل شفرات ضارة
    r"marshal\.loads\(",                   # تفريغ شفرات مسلسلة
    r"zlib\.decompress\(",                 # فك ضغط شفرات ضارة
    r"base64\.b64decode\(",                # فك تشفير شفرات
    r"eval\(",                             # تنفيذ ديناميكي
    r"exec\(",                             # تنفيذ أكواد
    r"compile\(",                          # تجميع أكواد
    r"__import__",                         # استيراد ديناميكي
    r"exec\(.+requests\.get.+\)",          # تنفيذ أكواد من الانترنت
    r"eval\(.+requests\.get.+\)",
    r"os\.popen\(",                        # تنفيذ أوامر النظام
    r"getUpdates\s*\(",                    # تواصل مع Telegram API
    r"sendMessage\s*\(",                   # إرسال رسائل عبر Telegram
    r"self\.rfile\.read\(",                # قراءة طلبات الشبكة
]

CONTEXT_SENSITIVE_PATTERNS = [
    r"chown\s+-R\s+\S+:\S+\s+/",           # تغيير ملكية ملفات النظام
    r"shutil\.rmtree\(",                   # حذف مجلدات
    r"subprocess\.run\(",                  # تنفيذ أوامر
    r"subprocess\.Popen\(",                # تنفيذ أوامر
    r"threading\.Thread\(",                # تنفيذ متوازي
    r"requests\.post\(",                   # إرسال بيانات
    r"open\([^)]*errors\s*=\s*[\"']ignore[\"']", # قراءة ملفات مع تجاهل الأخطاء
    r"HTTPServer\(",                       # تشغيل خادم ويب
    r"serve_forever\(",                    # تشغيل خادم دائم
    r"def\s+do_POST\(",                    # معالجة طلبات POST
    r"os\.walk\(",                         # مسح الملفات
    r"os\.system",                         # تنفيذ أوامر النظام
    r"reboot\s+-f",                        # إعادة التشغيل القسري
    r"poweroff\s+-f",                      # إيقاف الطاقة قسرياً
    r"pkill\s+-9",                         # قتل عمليات بالإكراه
    r"while\s+True\s*:",                   # حلقات لا نهائية
    r"os\.listdir\(",                      # قراءة محتويات المجلدات
    r"os\.remove\(",                       # حذف ملفات
]

WHITELIST_PATHS = [
    r"/var/www/.*",
    r"/tmp/.*",
    r"/home/[^/]+/projects/.*",
    r"/app/.*",
    r"/opt/.*",
    r"/usr/local/.*"
]

SAFE_COMMANDS = [
    r"ls\s+-l",
    r"df\s+-h",
    r"git\s+pull",
    r"npm\s+install",
    r"pip\s+install",
    r"apt\s+install",
    r"yum\s+install",
    r"docker\s+run",
    r"docker\s+build",
    r"chmod\s+[0-7]{3,4}\s+/var/www/.*",
    r"chown\s+[^:]+:[^:]+\s+/var/www/.*"
]

SAFE_DOMAINS = [
    r"https?://(www\.)?(github|gitlab|bitbucket|pypi|npmjs)\.(com|org)/.*",
    r"https?://(api\.)?(google|microsoft|amazon|docker|ubuntu)\.(com|org)/.*",
    r"https?://raw\.githubusercontent\.com/.*"
]

SENSITIVE_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/proc/self",
    "/root",
    "/home",
    "/.ssh",
    "/.bash_history",
    "/.env",
    "/.config",
    "/.git/config",
    "/appsettings.json"
]

# ============ دالة فحص الأمان الذكية ============
def security_scan(content):
    for pattern in ABSOLUTE_MALICIOUS_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            return True, f"تم اكتشاف نمط خبيث مطلق: {pattern}"
    
    for pattern in CONTEXT_SENSITIVE_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            safe_path = any(re.search(wp, content, re.IGNORECASE) for wp in WHITELIST_PATHS)
            if safe_path:
                continue
                
            safe_command = any(re.search(cmd, content, re.IGNORECASE) for cmd in SAFE_COMMANDS)
            if safe_command:
                continue
                
            safe_domain = any(re.search(domain, content, re.IGNORECASE) for domain in SAFE_DOMAINS)
            if safe_domain:
                continue
                
            if is_in_comment(content, pattern):
                continue
                
            return True, f"تم اكتشاف نمط مشبوه في سياق غير آمن: {pattern}"
    
    for sensitive_path in SENSITIVE_FILES:
        if re.search(re.escape(sensitive_path), content, re.IGNORECASE):
            safe_context = any(re.search(wp, content, re.IGNORECASE) for wp in WHITELIST_PATHS)
            if not safe_context:
                if is_in_comment(content, sensitive_path):
                    continue
                    
                return True, f"محاولة الوصول إلى مسار حساس: {sensitive_path}"
    
    return False, ""

def is_in_comment(content, pattern):
    lines = content.split('\n')
    for line in lines:
        if re.search(pattern, line, re.IGNORECASE):
            stripped_line = line.lstrip()
            if stripped_line.startswith('#'):
                return True
            if stripped_line.startswith('"""') or stripped_line.startswith("'''"):
                return True
    return False

def extract_snippet(content, reason, max_length=200):
    pattern = reason.split(': ')[-1]
    match = re.search(pattern, content, re.IGNORECASE)
    if not match:
        return "لم يتم العثور على الموقع الدقيق"
    
    start = max(0, match.start() - 30)
    end = min(len(content), match.end() + 30)
    snippet = content[start:end]
    snippet = re.sub(r'[_*`\[\]]', '', snippet)
    
    if start > 0:
        snippet = '...' + snippet
    if end < len(content):
        snippet = snippet + '...'
    
    if len(snippet) > max_length:
        snippet = snippet[:max_length] + '...'
        
    return snippet

# ============ دالة عرض بلاك الهكر ============
def show_hacker_banner():
    banner = r"""
██████╗ ██╗      █████╗  ██████╗██╗  ██╗
██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝
██████╔╝██║     ███████║██║     █████╔╝ 
██╔══██╗██║     ██╔══██║██║     ██╔═██╗ 
██████╔╝███████╗██║  ██║╚██████╗██║  ██╗
╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
"""
    print(banner)
    print("( BLACK - The Ultimate Bot System )")

# ============ الدوال المساعدة ============
def is_venv():
    """تحقق إذا كان البرنامج يعمل في بيئة افتراضية"""
    return hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)

def check_allowed(user_id):
    global bot_enabled
    
    # إذا كان البوت في وضع الصيانة والمستخدم ليس أدمن
    if not bot_enabled and user_id not in admin_list:
        return False, "⛔ البوت في وضع الصيانة حالياً. فقط الأدمن يمكنهم استخدامه.", False
    
    if user_id in admin_list or user_id in allowed_users:
        return True, "", False
    
    try:
        member = bot.get_chat_member(channel, user_id)
        if member.status in ['left', 'kicked']:
            return False, f"⚠️ يجب الاشتراك في القناة: {channel} قبل استخدام البوت.\nاضغط على الزر للاشتراك.", True
    except Exception:
        pass
    
    allowed_users.add(user_id)
    return True, "", False

def get_user_main_folder(user_id):
    folder = os.path.join(uploaded_files_dir, f"bot_{user_id}")
    if not os.path.exists(folder):
        os.makedirs(folder)
    return folder

def get_next_bot_number(user_id):
    user_folder = get_user_main_folder(user_id)
    existing = [
        d for d in os.listdir(user_folder)
        if os.path.isdir(os.path.join(user_folder, d)) and d.startswith("bot_")
    ]
    numbers = []
    for folder in existing:
        try:
            num = int(folder.split("_")[-1])
            numbers.append(num)
        except:
            pass
    return max(numbers) + 1 if numbers else 1

def install_library_with_retry(library_name, chat_id=None, install_path=None):
    """دالة محسنة لتثبيت المكتبات مع إعادة المحاولة والتقارير التفصيلية"""
    install_name = LIBRARY_ALIASES.get(library_name, library_name)
    
    # تحديد أوامر التثبيت المناسبة لنوع البيئة
    if is_venv():
        # في البيئات الافتراضية، لا نستخدم --user
        base_commands = [
            [sys.executable, "-m", "pip", "install", install_name],
            [sys.executable, "-m", "pip", "install", "--upgrade", install_name],
            [sys.executable, "-m", "pip", "install", "--no-cache-dir", install_name]
        ]
    else:
        # في البيئات العامة، نستخدم --user
        base_commands = [
            [sys.executable, "-m", "pip", "install", install_name],
            [sys.executable, "-m", "pip", "install", "--user", install_name],
            [sys.executable, "-m", "pip", "install", "--upgrade", install_name],
            [sys.executable, "-m", "pip", "install", "--user", "--upgrade", install_name],
            [sys.executable, "-m", "pip", "install", "--no-cache-dir", install_name]
        ]
    
    # إضافة أوامر التثبيت في مسار مخصص إذا تم توفيره
    if install_path:
        base_commands.insert(0, [
            sys.executable, "-m", "pip", "install", "--target", install_path, install_name
        ])
    
    attempts = base_commands
    
    error_messages = []
    for i, cmd in enumerate(attempts, 1):
        try:
            if chat_id:
                bot.send_message(chat_id, f"🔄 المحاولة {i}: تثبيت {install_name}...")
            
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                if chat_id:
                    bot.send_message(chat_id, f"✅ تم تثبيت {install_name} بنجاح.")
                return True
            else:
                error_msg = f"فشل تثبيت {install_name} (المحاولة {i}):\n"
                if result.stdout:
                    error_msg += f"الإخراج: {result.stdout[:500]}\n"
                if result.stderr:
                    error_msg += f"الخطأ: {result.stderr[:500]}"
                error_messages.append(error_msg)
                
        except subprocess.TimeoutExpired:
            error_msg = f"انتهى الوقت المحدد لتثبيت {install_name} (المحاولة {i})"
            error_messages.append(error_msg)
        except Exception as e:
            error_msg = f"خطأ غير متوقع أثناء تثبيت {install_name} (المحاولة {i}): {str(e)}"
            error_messages.append(error_msg)
    
    # إذا فشلت جميع المحاولات
    full_error = "\n\n".join(error_messages)
    if chat_id:
        bot.send_message(chat_id, f"❌ فشل تثبيت {install_name} بعد {len(attempts)} محاولات.")
    bot.send_message(ADMIN_ID, f"❌ فشل تثبيت {install_name} للمستخدم {chat_id}:\n{full_error}")
    return False

def auto_install_libraries(script_path, chat_id=None):
    """دالة محسنة لتثبيت المكتبات مع التعامل مع مشكلات asyncio"""
    try:
        # إنشاء مجلد مكتبات مخصص
        folder_path = os.path.dirname(script_path)
        libs_dir = os.path.join(folder_path, "libs")
        os.makedirs(libs_dir, exist_ok=True)
        
        # إضافة مجلد المكتبات إلى مسار بايثون
        sys.path.append(libs_dir)
        
        with open(script_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # استخراج المكتبات المطلوبة
        modules = set(re.findall(
            r'(?:^|\n)\s*(?:import|from)\s+([a-zA-Z_][a-zA-Z0-9_]*)',
            content
        ))
        
        # إضافة مكتبات من متطلبات النصوص
        requirements = set(re.findall(
            r'^\s*#\s*requires?:\s*([^\n]+)',
            content, re.MULTILINE | re.IGNORECASE
        ))
        
        if requirements:
            modules.update(chain.from_iterable(req.split(',') for req in requirements))

        # إضافة مكتبات من التعليقات الخاصة
        custom_imports = set(re.findall(
            r'^\s*#\s*install:\s*([^\n]+)',
            content, re.MULTILINE | re.IGNORECASE
        ))
        
        if custom_imports:
            modules.update(chain.from_iterable(imp.split(',') for imp in custom_imports))

        failed_installs = []
        for module in modules:
            if module in STANDARD_LIBS:
                continue
                
            # استخدام اسم التثبيت الصحيح إن وجد
            install_name = LIBRARY_ALIASES.get(module, module)
            
            # محاولة استيراد المكتبة مع التعامل مع asyncio
            try:
                # إنشاء حلقة أحداث جديدة إذا لزم الأمر
                try:
                    loop = asyncio.get_event_loop()
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                
                importlib.import_module(module)
                # إذا نجح الاستيراد، المكتبة مثبتة
                continue
            except ImportError:
                # إذا فشل الاستيراد، نحاول التثبيت في المسار المخصص
                success = install_library_with_retry(install_name, chat_id, libs_dir)
                if not success:
                    failed_installs.append(install_name)
            except Exception as e:
                print(f"خطأ أثناء استيراد {module}: {e}")
        
        if failed_installs:
            error_msg = "❌ فشل تثبيت المكتبات التالية: " + ", ".join(failed_installs)
            if chat_id:
                bot.send_message(chat_id, error_msg)
            bot.send_message(ADMIN_ID, f"فشل تثبيت مكتبات للمستخدم {chat_id}: {error_msg}")
            return False
        
        return True
        
    except Exception as e:
        error_msg = f"خطأ في التثبيت التلقائي: {str(e)}\n{traceback.format_exc()}"
        if chat_id:
            bot.send_message(chat_id, "❌ حدث خطأ أثناء تثبيت المكتبات.")
        bot.send_message(ADMIN_ID, error_msg)
        return False

def install_requirements(folder, chat_id=None):
    """دالة محسنة لتثبيت متطلبات requirements.txt"""
    req_file = os.path.join(folder, 'requirements.txt')
    if os.path.exists(req_file):
        # إنشاء مجلد مكتبات مخصص
        libs_dir = os.path.join(folder, "libs")
        os.makedirs(libs_dir, exist_ok=True)
        
        # إضافة مجلد المكتبات إلى مسار بايثون
        sys.path.append(libs_dir)
        
        if chat_id:
            bot.send_message(chat_id, f"🔄 جاري تثبيت المتطلبات من {req_file} ...")
        
        # تحديد أوامر التثبيت المناسبة
        if is_venv():
            commands = [
                [sys.executable, "-m", "pip", "install", "-r", req_file],
                [sys.executable, "-m", "pip", "install", "--upgrade", "-r", req_file],
                [sys.executable, "-m", "pip", "install", "--no-cache-dir", "-r", req_file],
                [sys.executable, "-m", "pip", "install", "--target", libs_dir, "-r", req_file]
            ]
        else:
            commands = [
                [sys.executable, "-m", "pip", "install", "-r", req_file],
                [sys.executable, "-m", "pip", "install", "--user", "-r", req_file],
                [sys.executable, "-m", "pip", "install", "--upgrade", "-r", req_file],
                [sys.executable, "-m", "pip", "install", "--user", "--upgrade", "-r", req_file],
                [sys.executable, "-m", "pip", "install", "--no-cache-dir", "-r", req_file],
                [sys.executable, "-m", "pip", "install", "--target", libs_dir, "-r", req_file]
            ]
        
        error_messages = []
        for i, cmd in enumerate(commands, 1):
            try:
                if chat_id:
                    bot.send_message(chat_id, f"🔄 المحاولة {i}: جاري التثبيت...")
                
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=300
                )
                
                if result.returncode == 0:
                    if chat_id:
                        bot.send_message(chat_id, f"✅ تم تثبيت المتطلبات بنجاح.")
                    return True
                else:
                    error_msg = f"فشل تثبيت المتطلبات (المحاولة {i}):\n"
                    if result.stdout:
                        error_msg += f"الإخراج: {result.stdout[:500]}\n"
                    if result.stderr:
                        error_msg += f"الخطأ: {result.stderr[:500]}"
                    error_messages.append(error_msg)
                    
            except subprocess.TimeoutExpired:
                error_msg = f"انتهى الوقت المحدد لتثبيت المتطلبات (المحاولة {i})"
                error_messages.append(error_msg)
            except Exception as e:
                error_msg = f"خطأ غير متوقع أثناء تثبيت المتطلبات (المحاولة {i}): {str(e)}"
                error_messages.append(error_msg)
        
        # إذا فشلت جميع المحاولات
        full_error = "\n\n".join(error_messages)
        if chat_id:
            bot.send_message(chat_id, "❌ فشل تثبيت المتطلبات.")
        bot.send_message(ADMIN_ID, f"❌ فشل تثبيت المتطلبات للمستخدم {chat_id}:\n{full_error}")
        return False
    
    return True

def extract_token_from_script(script_path):
    try:
        with open(script_path, 'r', encoding='utf-8') as script_file:
            content = script_file.read()
            token_match = re.search(r"[\"']([0-9]{9,10}:[A-Za-z0-9_-]+)[\"']", content)
            if token_match:
                return token_match.group(1)
            else:
                print(f"[WARNING] لم يتم العثور على توكن في {script_path}")
    except Exception as e:
        print(f"[ERROR] فشل استخراج التوكن من {script_path}: {e}")
    return None

# ============ الدوال الجديدة لمعالجة asyncio ============
def is_async_script(script_path):
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            content = f.read()
            return 'import asyncio' in content or 'async def' in content or 'import aiogram' in content
    except:
        return False

def run_async_bot(script_path, env):
    try:
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        spec = importlib.util.spec_from_file_location("user_bot", script_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        if hasattr(module, 'main') and asyncio.iscoroutinefunction(module.main):
            loop.run_until_complete(module.main())
        elif hasattr(module, 'start') and asyncio.iscoroutinefunction(module.start):
            loop.run_until_complete(module.start())
        elif hasattr(module, 'run') and asyncio.iscoroutinefunction(module.run):
            loop.run_until_complete(module.run())
        else:
            raise RuntimeError("لم يتم العثور على دالة غير متزامنة قابلة للتشغيل (main/start/run)")
    except Exception as e:
        logging.error(f"خطأ في البوت غير المتزامن: {e}")
        raise

def run_sync_bot(script_path, env):
    process = subprocess.Popen(
        [sys.executable, script_path],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding='utf-8'
    )
    process.wait()

def run_subprocess(script_path, env):
    try:
        # إضافة مجلد المكتبات إلى مسار بايثون للعملية الفرعية
        folder_path = os.path.dirname(script_path)
        libs_dir = os.path.join(folder_path, "libs")
        
        # تحديث متغيرات البيئة لمسار بايثون
        env_copy = env.copy()
        if 'PYTHONPATH' in env_copy:
            env_copy['PYTHONPATH'] = f"{libs_dir}:{env_copy['PYTHONPATH']}"
        else:
            env_copy['PYTHONPATH'] = libs_dir
        
        if is_async_script(script_path):
            run_async_bot(script_path, env_copy)
        else:
            run_sync_bot(script_path, env_copy)
    except Exception as e:
        logging.error(f"فشل تشغيل البوت: {e}")

# ============ الدوال الرئيسية للتشغيل ============
def run_script(script_path, chat_id, folder_path, bot_number, original_filename):
    try:
        bot_name = os.path.basename(original_filename)
        user_info = bot.get_chat(chat_id)
        
        # استخراج التوكن من الملف
        token = extract_token_from_script(script_path)
        if token:
            env = os.environ.copy()
            env['LANG'] = 'en_US.UTF-8'
            env['LC_ALL'] = 'en_US.UTF-8'
            
            if sys.platform == 'win32':
                env['PYTHONASYNCIODEBUG'] = '1'
                env['ASYNCIO_DEBUG'] = '1'
            
            mp_process = Process(target=run_subprocess, args=(script_path, env))
            mp_process.start()
            
            bot_scripts[f"{chat_id}_{bot_number}"] = {
                'mp_process': mp_process,
                'folder_path': folder_path,
                'file': script_path,
                'name': bot_name,
                'original_filename': original_filename
            }
            
            # رسالة تشغيل بدون التحقق من صحة التوكن
            bot.send_message(chat_id, f"✅ تم تشغيل البوت بنجاح.")
            
            # إنشاء زر الإيقاف
            markup = types.InlineKeyboardMarkup()
            button = types.InlineKeyboardButton(
                f"🔴 إيقاف  {original_filename}",
                callback_data=f"stop_delete_{chat_id}_{bot_number}"
            )
            markup.add(button)
            
            bot.send_message(
                chat_id,
                f"🚀 تم رفع وتشغيل {original_filename} بنجاح. استخدم الزر أدناه لإيقافه وحذفه:",
                reply_markup=markup
            )
            
        else:
            bot.send_message(chat_id, "❌ لم يتم العثور على توكن صالح في الملف.")
            
    except Exception as e:
        error_msg = f"❌ حدث خطأ أثناء تشغيل البوت: {e}\n{traceback.format_exc()}"
        bot.send_message(chat_id, error_msg)
        bot.send_message(ADMIN_ID, f"خطأ في تشغيل البوت للمستخدم {chat_id}:\n{error_msg}")

def stop_and_delete_bot(chat_id, bot_number):
    key = f"{chat_id}_{bot_number}"
    if key in bot_scripts:
        bot_info = bot_scripts[key]
        mp_process = bot_info.get('mp_process')
        bot_name = bot_info.get('name', f"بوت {bot_number}")
        
        if mp_process:
            try:
                if mp_process.is_alive():
                    mp_process.terminate()
                    mp_process.join(timeout=5)
                    if mp_process.is_alive():
                        mp_process.kill()
            except Exception as e:
                print(f"خطأ أثناء إيقاف العملية: {e}")
        
        folder_path = bot_info.get('folder_path')
        if folder_path and os.path.exists(folder_path):
            try:
                # التأكيد على حذف المجلد نهائياً
                shutil.rmtree(folder_path, ignore_errors=True)
                print(f"تم حذف المجلد نهائياً: {folder_path}")
            except Exception as e:
                print(f"فشل حذف المجلد: {e}")
        
        # إزالة البوت من القائمة بعد الحذف
        if key in bot_scripts:
            del bot_scripts[key]
        return bot_name
    return None

def download_files_func(chat_id):
    try:
        files_list = []
        for root, dirs, files in os.walk(uploaded_files_dir):
            for file in files:
                files_list.append(os.path.join(root, file))
        if not files_list:
            bot.send_message(chat_id, "⚠️ لا توجد ملفات مرفوعة.")
            return
        for file_path in files_list:
            if os.path.isfile(file_path):
                with open(file_path, 'rb') as f:
                    bot.send_document(chat_id, f)
    except Exception as e:
        bot.send_message(chat_id, f"❌ حدث خطأ أثناء تنزيل الملفات: {e}")

# ============ معالجات الرسائل ============
@bot.message_handler(func=lambda m: m.from_user.id in blocked_users)
def handle_blocked(message):
    bot.send_message(message.chat.id, "⚠️ أنت محظور من استخدام البوت.")

@bot.message_handler(commands=['start'])
def send_welcome(message):
    user_id = message.from_user.id
    allowed_flag, msg, need_subscribe = check_allowed(user_id)
    if not allowed_flag:
        if need_subscribe:
            markup = types.InlineKeyboardMarkup()
            join_button = types.InlineKeyboardButton(
                'اشترك في القناة',
                url=f"https://t.me/{channel.lstrip('@')}"
            )
            markup.add(join_button)
            bot.send_message(message.chat.id, msg, reply_markup=markup)
        else:
            bot.send_message(message.chat.id, msg)
        return

    info_text = (
        f"👤 معلوماتك:\n"
        f"• ID: {user_id}\n"
        f"• Username: @{message.from_user.username if message.from_user.username else 'غير متوفر'}\n"
        f"• الاسم: {message.from_user.first_name}"
    )
    
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton('📤 رفع ملف', callback_data='upload'),
        types.InlineKeyboardButton('📥 تنزيل مكتبة', callback_data='download_lib'),
        types.InlineKeyboardButton('⚡ سرعة البوت', callback_data='speed'),
        types.InlineKeyboardButton(
            '🔔 قناة المطور',
            url=f"https://t.me/TP_Q_T"
        )
    )
    if user_id in admin_list:
        markup.add(types.InlineKeyboardButton('⚙️ لوحة الأدمن', callback_data='admin_panel'))
    
    # إرسال الرسالة مع الصورة الثابتة
    try:
        bot.send_photo(
            message.chat.id,
            STATIC_AVATAR_URL,
            caption=f"مرحباً، {message.from_user.first_name}! 👋\n{info_text}\n✨ استخدم الأزرار أدناه للتحكم:",
            reply_markup=markup
        )
    except Exception as e:
        # إذا فشل إرسال الصورة، نرسل الرسالة بدونها
        bot.send_message(
            message.chat.id,
            f"مرحباً، {message.from_user.first_name}! 👋\n{info_text}\n✨ استخدم الأزرار أدناه للتحكم:",
            reply_markup=markup
        )

# ============ أوامر البوت التفاعلية ============
@bot.callback_query_handler(func=lambda call: call.data == 'upload')
def ask_to_upload_file(call):
    bot.send_message(call.message.chat.id, "📄 من فضلك، أرسل الملف الذي تريد رفعه.")

@bot.callback_query_handler(func=lambda call: call.data == 'download_lib')
def ask_library_name(call):
    bot.send_message(call.message.chat.id, "📥 أرسل اسم المكتبة التي تريد تنزيلها.")
    bot.register_next_step_handler(call.message, install_library)

def install_library(message):
    library_name = message.text.strip()
    try:
        importlib.import_module(library_name)
        bot.send_message(message.chat.id, f"✅ المكتبة {library_name} مثبتة مسبقاً.")
        return
    except ImportError:
        pass
    
    # استخدام دالة التثبيت المحسنة
    success = install_library_with_retry(library_name, message.chat.id)
    if success:
        bot.send_message(message.chat.id, f"✅ تم تثبيت المكتبة {library_name} بنجاح.")
    else:
        bot.send_message(message.chat.id, f"❌ فشل في تثبيت المكتبة {library_name} بعد عدة محاولات.")

@bot.callback_query_handler(func=lambda call: call.data == 'speed')
def bot_speed_info(call):
    try:
        start_time = time.time()
        response = requests.get(f'https://api.telegram.org/bot{TOKEN}/getMe')
        latency = time.time() - start_time
        if response.ok:
            bot.send_message(call.message.chat.id, f"⚡ سرعة البوت: {latency:.2f} ثانية.")
        else:
            bot.send_message(call.message.chat.id, "⚠️ فشل في الحصول على سرعة البوت.")
    except Exception as e:
        bot.send_message(call.message.chat.id, f"❌ حدث خطأ أثناء فحص سرعة البوت: {e}")

# استقبال الملفات
@bot.message_handler(content_types=['document'])
def handle_file(message):
    user_id = message.from_user.id
    allowed_flag, msg, need_subscribe = check_allowed(user_id)
    if not allowed_flag:
        if need_subscribe:
            markup = types.InlineKeyboardMarkup()
            join_button = types.InlineKeyboardButton(
                'اشترك في القناة',
                url=f"https://t.me/{channel.lstrip('@')}"
            )
            markup.add(join_button)
            bot.send_message(message.chat.id, msg, reply_markup=markup)
        else:
            bot.send_message(message.chat.id, msg)
        return

    try:
        file_id = message.document.file_id
        file_info = bot.get_file(file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        original_file_name = message.document.file_name

        user_main_folder = get_user_main_folder(user_id)
        bot_number = get_next_bot_number(user_id)
        bot_folder = os.path.join(user_main_folder, f"bot_{bot_number}")
        os.makedirs(bot_folder, exist_ok=True)

        # ======== بدء الفحص الأمني الذكي ========
        temp_file_path = os.path.join(bot_folder, original_file_name)
        with open(temp_file_path, 'wb') as temp_file:
            temp_file.write(downloaded_file)
            
        # الفحص الأمني للمستخدمين العاديين فقط
        if user_id not in admin_list:
            try:
                with open(temp_file_path, 'r', encoding='utf-8') as f:
                    file_content = f.read()
            except UnicodeDecodeError:
                with open(temp_file_path, 'rb') as f:
                    file_content = f.read().decode('utf-8', errors='ignore')
            
            is_malicious, reason = security_scan(file_content)
            if is_malicious:
                os.remove(temp_file_path)
                shutil.rmtree(bot_folder, ignore_errors=True)
                snippet = extract_snippet(file_content, reason)
                bot.reply_to(message, "⛔ تم رفض الملف: محتوى غير مسموح به.")
                
                try:
                    admin_msg = (
                        f"❌ تم رفض ملف خبيث:\n"
                        f"• المستخدم: {user_id} ({message.from_user.first_name})\n"
                        f"• الملف: {original_file_name}\n"
                        f"• السبب: {reason}\n\n"
                        f"مقتطف الكود:\n"
                        f"{snippet}"
                    )
                    bot.send_message(ADMIN_ID, admin_msg)
                except Exception as admin_error:
                    print(f"فشل إرسال التنبيه للأدمن: {admin_error}")
                return
        # ======== نهاية الفحص الأمني ========

        main_file_candidate = None

        if original_file_name.endswith('.zip'):
            with zipfile.ZipFile(temp_file_path, 'r') as zip_ref:
                zip_ref.extractall(bot_folder)
            os.remove(temp_file_path)
        elif original_file_name.endswith('.py'):
            dest_file = os.path.join(bot_folder, original_file_name)
            os.rename(temp_file_path, dest_file)
            main_file_candidate = dest_file
            
            # تثبيت المكتبات المطلوبة
            if not auto_install_libraries(dest_file, message.chat.id):
                bot.send_message(message.chat.id, "⚠️ حدثت أخطاء أثناء تثبيت المكتبات. قد لا يعمل البوت بشكل صحيح.")
        else:
            bot.reply_to(message, "⚠️ يُسمح برفع ملفات بايثون أو zip فقط.")
            return

        # تثبيت متطلبات requirements.txt إن وجدت
        install_requirements(bot_folder, message.chat.id)
        
        main_file = None
        
        # تحديد الملف الرئيسي للتشغيل
        if main_file_candidate:
            main_file = main_file_candidate
        else:
            candidate_run = os.path.join(bot_folder, "run.py")
            candidate_bot = os.path.join(bot_folder, "bot.py")
            candidate_main = os.path.join(bot_folder, "main.py")

            if os.path.exists(candidate_run):
                main_file = candidate_run
            elif os.path.exists(candidate_bot):
                main_file = candidate_bot
            elif os.path.exists(candidate_main):
                main_file = candidate_main

        if not main_file:
            bot.send_message(
                message.chat.id,
                "❓ لم أتمكن من العثور على الملف الرئيسي لتشغيل البوت.\nيرجى إرسال اسم الملف الذي ترغب بتشغيله."
            )
            bot_scripts[f"{user_id}_{bot_number}"] = {
                'folder_path': bot_folder,
                'original_filename': original_file_name
            }
            bot.register_next_step_handler(message, get_custom_file_to_run)
        else:
            run_script(main_file, message.chat.id, bot_folder, bot_number, original_file_name)
    except Exception as e:
        error_msg = f"❌ حدث خطأ غير متوقع: {str(e)}\n{traceback.format_exc()}"
        bot.reply_to(message, error_msg)
        bot.send_message(ADMIN_ID, f"خطأ في معالجة الملف للمستخدم {user_id}:\n{error_msg}")

def get_custom_file_to_run(message):
    try:
        chat_id = message.chat.id
        keys = [k for k in bot_scripts if k.startswith(f"{chat_id}_")]
        if not keys:
            bot.send_message(chat_id, "❌ لا يوجد بيانات محفوظة للمجلد.")
            return
        key = keys[0]
        folder_path = bot_scripts[key]['folder_path']
        original_filename = bot_scripts[key].get('original_filename', 'الملف')
        custom_file_path = os.path.join(folder_path, message.text.strip())
        
        if os.path.exists(custom_file_path):
            bot_number = key.split('_')[-1]
            run_script(custom_file_path, chat_id, folder_path, bot_number, original_filename)
        else:
            bot.send_message(chat_id, "❌ الملف الذي حددته غير موجود. تأكد من الاسم وحاول مرة أخرى.")
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ حدث خطأ: {e}")

# معالج جديد للزر المدمج (إيقاف وحذف)
@bot.callback_query_handler(func=lambda call: call.data.startswith('stop_delete_'))
def callback_stop_delete_bot(call):
    parts = call.data.split('_')
    if len(parts) >= 4:
        chat_id = parts[2]
        bot_number = parts[3]
        bot_name = stop_and_delete_bot(chat_id, bot_number)
        if bot_name:
            # إزالة الزر بعد الضغط عليه
            bot.edit_message_reply_markup(
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                reply_markup=None
            )
            bot.send_message(call.message.chat.id, f"🔴 تم إيقاف وحذف {bot_name} نهائياً من السيرفر.")
        else:
            bot.send_message(call.message.chat.id, "⚠️ لا يوجد بوت يعمل بهذا الرقم.")

# ============ لوحة الأدمن التفاعلية ============
@bot.callback_query_handler(func=lambda call: call.data == 'admin_panel')
def show_admin_panel(call):
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton('🚫 حظر مستخدم', callback_data='prompt_ban'),
        types.InlineKeyboardButton('✅ فك الحظر', callback_data='prompt_unban'),
        types.InlineKeyboardButton('🔓 السماح', callback_data='prompt_allow'),
        types.InlineKeyboardButton('🗑️ حذف مستخدم', callback_data='prompt_remove'),
        types.InlineKeyboardButton('📋 عرض الملفات', callback_data='list_files'),
        types.InlineKeyboardButton('📥 تنزيل الملفات', callback_data='download_files'),
        types.InlineKeyboardButton('🗑️ حذف مكتبة', callback_data='prompt_remove_lib'),
        types.InlineKeyboardButton('📢 بث رسالة', callback_data='prompt_broadcast'),
        types.InlineKeyboardButton('🔴 إيقاف بوت', callback_data='prompt_stopfile'),
        types.InlineKeyboardButton('⏹️ إيقاف جميع البوتات', callback_data='stopall'),
        types.InlineKeyboardButton('🗑️ حذف جميع البوتات', callback_data='deleteall'),
        types.InlineKeyboardButton('➕ إضافة أدمن', callback_data='prompt_add_admin'),
        types.InlineKeyboardButton('➖ إزالة أدمن', callback_data='prompt_remove_admin'),
        types.InlineKeyboardButton('⏸ إيقاف البوت', callback_data='disable_bot'),
        types.InlineKeyboardButton('▶️ تشغيل البوت', callback_data='enable_bot')
    )
    bot.send_message(call.message.chat.id, "🛠️ لوحة الأدمن التفاعلية:", reply_markup=markup)

# ============ وظائف الأدمن التفاعلية ============
@bot.callback_query_handler(func=lambda call: call.data == 'disable_bot')
def disable_bot(call):
    global bot_enabled
    if bot_enabled:
        bot_enabled = False
        bot.send_message(call.message.chat.id, "⏸ تم إيقاف البوت بنجاح. وضع الصيانة مفعّل الآن.")
    else:
        bot.send_message(call.message.chat.id, "ℹ️ البوت متوقف بالفعل في وضع الصيانة.")

@bot.callback_query_handler(func=lambda call: call.data == 'enable_bot')
def enable_bot(call):
    global bot_enabled
    if not bot_enabled:
        bot_enabled = True
        bot.send_message(call.message.chat.id, "▶️ تم تشغيل البوت بنجاح. البوت يعمل الآن بشكل طبيعي.")
    else:
        bot.send_message(call.message.chat.id, "ℹ️ البوت يعمل بالفعل بشكل طبيعي.")

@bot.callback_query_handler(func=lambda call: call.data == 'prompt_ban')
def prompt_ban(call):
    msg = bot.send_message(call.message.chat.id, "أرسل معرف المستخدم الذي تريد حظره:")
    bot.register_next_step_handler(msg, process_ban)

def process_ban(message):
    try:
        user_id = int(message.text.strip())
        blocked_users.add(user_id)
        bot.send_message(message.chat.id, f"🚫 تم حظر المستخدم {user_id}.")
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ حدث خطأ: {e}")

@bot.callback_query_handler(func=lambda call: call.data == 'prompt_unban')
def prompt_unban(call):
    msg = bot.send_message(call.message.chat.id, "أرسل معرف المستخدم الذي تريد فك حظره:")
    bot.register_next_step_handler(msg, process_unban)

def process_unban(message):
    try:
        user_id = int(message.text.strip())
        blocked_users.discard(user_id)
        bot.send_message(message.chat.id, f"✅ تم فك الحظر عن المستخدم {user_id}.")
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ حدث خطأ: {e}")

@bot.callback_query_handler(func=lambda call: call.data == 'prompt_allow')
def prompt_allow(call):
    msg = bot.send_message(call.message.chat.id, "أرسل معرف المستخدم الذي تريد السماح له:")
    bot.register_next_step_handler(msg, process_allow)

def process_allow(message):
    try:
        user_id = int(message.text.strip())
        allowed_users.add(user_id)
        bot.send_message(message.chat.id, f"✅ تم السماح للمستخدم {user_id} باستخدام البوت.")
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ حدث خطأ: {e}")

@bot.callback_query_handler(func=lambda call: call.data == 'prompt_remove')
def prompt_remove(call):
    msg = bot.send_message(call.message.chat.id, "أرسل معرف المستخدم الذي تريد حذفه من قائمة المسموح لهم:")
    bot.register_next_step_handler(msg, process_remove)

def process_remove(message):
    try:
        user_id = int(message.text.strip())
        allowed_users.discard(user_id)
        bot.send_message(message.chat.id, f"🗑️ تم حذف المستخدم {user_id} من قائمة المسموح لهم.")
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ حدث خطأ: {e}")

@bot.callback_query_handler(func=lambda call: call.data == 'list_files')
def callback_list_files(call):
    try:
        if not os.path.exists(uploaded_files_dir):
            bot.send_message(call.message.chat.id, "⚠️ لا توجد ملفات مرفوعة.")
            return
        files_list = []
        for root, dirs, files in os.walk(uploaded_files_dir):
            for file in files:
                files_list.append(os.path.join(root, file))
        if not files_list:
            bot.send_message(call.message.chat.id, "⚠️ لا توجد ملفات مرفوعة.")
        else:
            text = "📋 قائمة الملفات المرفوعة:\n" + "\n".join(files_list)
            if len(text) > 4000:
                with open("files_list.txt", "w", encoding="utf-8") as f:
                    f.write(text)
                with open("files_list.txt", "rb") as f:
                    bot.send_document(call.message.chat.id, f)
                os.remove("files_list.txt")
            else:
                bot.send_message(call.message.chat.id, text)
    except Exception as e:
        bot.send_message(call.message.chat.id, f"❌ حدث خطأ أثناء عرض الملفات: {e}")

@bot.callback_query_handler(func=lambda call: call.data == 'download_files')
def callback_download_files(call):
    download_files_func(call.message.chat.id)

@bot.callback_query_handler(func=lambda call: call.data == 'prompt_remove_lib')
def prompt_remove_lib(call):
    msg = bot.send_message(call.message.chat.id, "أرسل اسم المكتبة التي تريد حذفها:")
    bot.register_next_step_handler(msg, process_remove_lib)

def process_remove_lib(message):
    try:
        lib_name = message.text.strip()
        bot.send_message(message.chat.id, f"⏳ جاري حذف المكتبة {lib_name}...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "uninstall", "-y", lib_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        bot.send_message(message.chat.id, f"✅ تم حذف المكتبة {lib_name} نهائياً.")
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ فشل حذف المكتبة {lib_name}.\nالخطأ: {e}")

@bot.callback_query_handler(func=lambda call: call.data == 'prompt_broadcast')
def prompt_broadcast(call):
    msg = bot.send_message(call.message.chat.id, "أرسل الرسالة التي تريد بثها لجميع المستخدمين:")
    bot.register_next_step_handler(msg, process_broadcast)

def process_broadcast(message):
    try:
        broadcast_text = message.text
        count = 0
        target_users = allowed_users | admin_list
        for uid in target_users:
            try:
                bot.send_message(uid, f"📢 رسالة من الأدمن:\n\n{broadcast_text}")
                count += 1
            except Exception as e:
                print(f"Error sending broadcast to {uid}: {e}")
        bot.send_message(message.chat.id, f"✅ تم بث الرسالة إلى {count} مستخدم.")
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ حدث خطأ: {e}")

@bot.callback_query_handler(func=lambda call: call.data == 'prompt_stopfile')
def prompt_stopfile(call):
    msg = bot.send_message(call.message.chat.id, "أرسل البيانات بصيغة: <user_id> <bot_number> لإيقاف بوت محدد:")
    bot.register_next_step_handler(msg, process_stopfile)

def process_stopfile(message):
    try:
        parts = message.text.split()
        if len(parts) < 2:
            bot.send_message(message.chat.id, "⚠️ استخدم الصيغة: <user_id> <bot_number>")
            return
        chat_id = parts[0]
        bot_number = parts[1]
        bot_name = stop_and_delete_bot(chat_id, bot_number)
        if bot_name:
            bot.send_message(message.chat.id, f"🔴 تم إيقاف وحذف {bot_name} نهائياً من السيرفر.")
        else:
            bot.send_message(message.chat.id, "⚠️ لا يوجد بوت يعمل بهذا الرقم.")
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ حدث خطأ: {e}")

@bot.callback_query_handler(func=lambda call: call.data == 'stopall')
def stop_all(call):
    try:
        keys = list(bot_scripts.keys())
        count = 0
        for key in keys:
            bot_info = bot_scripts[key]
            mp_process = bot_info.get('mp_process')
            if mp_process:
                try:
                    if mp_process.is_alive():
                        mp_process.terminate()
                        mp_process.join(timeout=5)
                        if mp_process.is_alive():
                            mp_process.kill()
                        count += 1
                except:
                    pass
            folder_path = bot_info.get('folder_path')
            if folder_path and os.path.exists(folder_path):
                shutil.rmtree(folder_path, ignore_errors=True)
            del bot_scripts[key]
        bot.send_message(call.message.chat.id, f"🔴 تم إيقاف  {count} بوت وحذف ملفاتهم.")
    except Exception as e:
        bot.send_message(call.message.chat.id, f"❌ حدث خطأ: {e}")

@bot.callback_query_handler(func=lambda call: call.data == 'deleteall')
def delete_all(call):
    try:
        keys = list(bot_scripts.keys())
        for key in keys:
            bot_info = bot_scripts[key]
            mp_process = bot_info.get('mp_process')
            if mp_process:
                try:
                    if mp_process.is_alive():
                        mp_process.terminate()
                        mp_process.join(timeout=5)
                        if mp_process.is_alive():
                            mp_process.kill()
                except:
                    pass
            folder_path = bot_info.get('folder_path')
            if folder_path and os.path.exists(folder_path):
                shutil.rmtree(folder_path, ignore_errors=True)
            del bot_scripts[key]
        bot.send_message(call.message.chat.id, "🗑️ تم حذف جميع ملفات البوت وإيقاف جميع الجلسات.")
    except Exception as e:
        bot.send_message(call.message.chat.id, f"❌ حدث خطأ: {e}")

@bot.callback_query_handler(func=lambda call: call.data == 'prompt_add_admin')
def prompt_add_admin(call):
    msg = bot.send_message(call.message.chat.id, "أرسل معرف المستخدم لإضافته كأدمن:")
    bot.register_next_step_handler(msg, process_add_admin)

def process_add_admin(message):
    try:
        new_admin = int(message.text.strip())
        admin_list.add(new_admin)
        allowed_users.add(new_admin)
        bot.send_message(message.chat.id, f"✅ تمت إضافة المستخدم {new_admin} كأدمن.")
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ حدث خطأ: {e}")

@bot.callback_query_handler(func=lambda call: call.data == 'prompt_remove_admin')
def prompt_remove_admin(call):
    msg = bot.send_message(call.message.chat.id, "أرسل معرف الأدمن الذي تريد إزالته:")
    bot.register_next_step_handler(msg, process_remove_admin)

def process_remove_admin(message):
    try:
        rem_admin = int(message.text.strip())
        if rem_admin in admin_list and rem_admin != ADMIN_ID:
            admin_list.discard(rem_admin)
            allowed_users.discard(rem_admin)
            bot.send_message(message.chat.id, f"✅ تمت إزالة الأدمن {rem_admin}.")
        else:
            bot.send_message(message.chat.id, "⚠️ لا يمكن إزالة الأدمن الأساسي أو المستخدم غير موجود.")
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ حدث خطأ: {e}")

# ============ بدء التشغيل ============
if __name__ == "__main__":
    show_hacker_banner()
    print("✅ تم تحديث النظام لدعم الأسماء العربية والإنجليزية بشكل كامل")
    print("🔒 نظام الحماية يعمل بمستوى عالي من الكفاءة")
    print("🛠️ تم تحسين نظام تثبيت المكتبات بشكل كبير")
    print("📚 تم دعم جميع المكتبات غير القياسية على جميع الاستضافات")
    
    retry_delay = 1
    while True:
        try:
            bot.infinity_polling()
            retry_delay = 1
        except Exception as e:
            logging.error(f"Bot error: {e}")
            time.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, 60)

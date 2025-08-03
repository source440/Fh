import requests,telebot,json,time
from telebot import types
from telebot.apihelper import ApiTelegramException
ToBot = '7990246499:AAEX2HimA671ytnANPm_uqCxw19CxvlpaZ0' # - ( توكن بوتك .
UsBot = 'BlackAiPhotoBot' # - ( يوزر بوتك .
UsYou = 'B_Q_5' # - ( يوزرك .
PhBot = 'https://t.me/testphotoblack/2' # - ( رابط صورة .
IdEmo  = 5104841245755180586 # - ( 🔥 .
golden = telebot.TeleBot(ToBot) 
def generate_images(G8):
    try:
        tnt = {'User-Prompt': G8}
        response = requests.post('http://185.158.132.66:2010/api/tnt/tnt-black-image',json=tnt)
        return response.json().get("url-image")
    except:return None
@golden.message_handler(commands=['start'])
def SaWaD1(GMS):
    G5 = (f"""<b>☭ ⁞ اهـلا بــك عـزيـزي 「 <a href='tg://user?id={GMS.from_user.id}'>{GMS.from_user.first_name}</a> 」 فـي بـوت صـنع الصـور بـ الذكـاء الاصـطناعي .</b>
<b>☭ ⁞ اقــوئ بـوت في صـناعة الصور والدقـة الخـرافـية .</b>
<b>☭ ⁞ يمـكنك صـنع صـور هـنا او تـضيفـني لـ مجـموعتك والتفاعل مع الاعضاء .</b>
<b>☭ ⁞ عـندما تضـيفني في المجمـوعة ارسـل ⌝ <code>الاومر</code> ⌞ .</b>
<b>☭ ⁞ او اذا هـنا في المحـادثه فـقط ارسـل كـلامك .</b>""")
    GG = types.InlineKeyboardMarkup();G6 = types.InlineKeyboardButton('ضيـفني لــ مـجموعـتك',url=f'https://t.me/{UsBot}?startgroup=new');GG.add(G6);golden.send_photo(GMS.chat.id,f'{PhBot}',caption = G5,parse_mode = 'HTML',reply_markup = GG,reply_to_message_id = GMS.message_id)
@golden.message_handler(func = lambda GMS: GMS.chat.type == 'private' and not GMS.text.startswith('/'))
def SaWaD2(GMS):
    G7 = time.time();G8 = GMS.text;GG = types.InlineKeyboardMarkup()
    G6 = types.InlineKeyboardButton('𝖘𝖍𝖚𝖙 𝖚𝖕 𝖋𝖆𝖌𝖌𝖔𝖙',url=f'https://t.me/{UsYou}');GG.add(G6)
    G9 = golden.send_message(GMS.chat.id,(f"""<b>☭ ⁞</b> <a href='tg://user?id={GMS.from_user.id}'><b>{GMS.from_user.first_name}</b></a>
<b>☭ ⁞ انـتضر عـزيــزي .</b>"""),parse_mode = 'HTML',reply_markup = GG,reply_to_message_id = GMS.message_id,message_effect_id = IdEmo)
    G1 = generate_images(G8);G10 = 3;G11 = 10
    for attempt in range(G10):
        try:
            golden.delete_message(GMS.chat.id,G9.message_id)
            break
        except ApiTelegramException as x:
            if x.error_code == 429:time.sleep(G11)
            else:break
    if not G1:golden.send_message(GMS.chat.id,"❌",reply_to_message_id = GMS.message_id);return
    G12 = round(time.time() - G7,2);G13 = (f"""☭ ⁞ <a href='tg://user?id={GMS.from_user.id}'>{GMS.from_user.first_name}</a>.
☭ ⁞ <code>{G12}</code> ثـانيـة .""");G14 = []
    for G15 in G1:G14.append(types.InputMediaPhoto(G15))
    G14[0].caption = G13;G14[0].parse_mode = 'HTML'
    for attempt in range(G10):
        try:
            golden.send_media_group(GMS.chat.id,G14,reply_to_message_id = GMS.message_id)
            break
        except ApiTelegramException as x:
            if x.error_code == 429:
                GG = types.InlineKeyboardMarkup();G6 = types.InlineKeyboardButton('𝖘𝖍𝖚𝖙 𝖚𝖕 𝖋𝖆𝖌𝖌𝖔𝖙',url=f'https://t.me/{UsYou}')
                GG.add(G6)
                try:golden.send_message(GMS.chat.id,(f"""<b>☭ ⁞</b> <a href='tg://user?id={GMS.from_user.id}'><b>{GMS.from_user.first_name}</b></a>
<b>☭ ⁞ انـتضر عـزيــزي .</b>"""),parse_mode = 'HTML',reply_markup = GG,reply_to_message_id = GMS.message_id)
                except:pass
                time.sleep(G11)
            else:raise x
@golden.message_handler(commands=['ai'])
def handle_ai_command(GMS):
    G7 = time.time()
    G8 = GMS.text.split('/ai ')[1] if len(GMS.text.split('/ai ')) > 1 else None
    if not G8:return
    GG = types.InlineKeyboardMarkup()
    G6 = types.InlineKeyboardButton('𝖘𝖍𝖚𝖙 𝖚𝖕 𝖋𝖆𝖌𝖌𝖔𝖙',url=f'https://t.me/{UsYou}');GG.add(G6)
    G9 = golden.send_message(GMS.chat.id,(f"""<b>☭ ⁞</b> <a href='tg://user?id={GMS.from_user.id}'><b>{GMS.from_user.first_name}</b></a>
<b>☭ ⁞ انـتضر عـزيــزي .</b>"""),parse_mode = 'HTML',reply_markup = GG,reply_to_message_id = GMS.message_id)
    G1 = generate_images(G8);G10 = 3;G11 = 10
    for attempt in range(G10):
        try:
            golden.delete_message(GMS.chat.id,G9.message_id)
            break
        except ApiTelegramException as x:
            if x.error_code == 429:time.sleep(G11)
            else:break
    if not G1:golden.send_message(GMS.chat.id,"❌",reply_to_message_id = GMS.message_id);return
    G12 = round(time.time() - G7,2)
    G13 = f"""☭ ⁞ <a href='tg://user?id={GMS.from_user.id}'>{GMS.from_user.first_name}</a>.
☭ ⁞ <code>{G12}</code> ثـانيـة ."""
    G14 = []
    for G15 in G1:G14.append(types.InputMediaPhoto(G15))
    G14[0].caption = G13
    G14[0].parse_mode = 'HTML'
    for attempt in range(G10):
        try:
            golden.send_media_group(GMS.chat.id,G14,reply_to_message_id = GMS.message_id)
            break
        except ApiTelegramException as x:
            if x.error_code == 429:
                GG = types.InlineKeyboardMarkup();G6 = types.InlineKeyboardButton('𝖘𝖍𝖚𝖙 𝖚𝖕 𝖋𝖆𝖌𝖌𝖔𝖙',url=f'https://t.me/{UsYou}');GG.add(G6)
                try:golden.send_message(GMS.chat.id,(f"""<b>☭ ⁞</b> <a href='tg://user?id={GMS.from_user.id}'><b>{GMS.from_user.first_name}</b></a>
<b>☭ ⁞ انـتضر عـزيــزي .</b>"""),parse_mode = 'HTML',reply_markup = GG,reply_to_message_id = GMS.message_id)
                except:pass
                time.sleep(G11)
            else:raise x
@golden.message_handler(func = lambda GMS: GMS.text == 'الاوامر' and GMS.chat.type != 'private')
def G16(GMS):
    G17 = ("""<b>☭ ⁞ لـصنع الصـور ارسـل : /ai + الكلام .
☭ ⁞ مثـال :</b> <code>/ai قطة</code> .""")
    GG = types.InlineKeyboardMarkup()
    G6 = types.InlineKeyboardButton('𝖘𝖍𝖚𝖙 𝖚𝖕 𝖋𝖆𝖌𝖌𝖔𝖙',url=f'https://t.me/{UsYou}');GG.add(G6)
    golden.send_message(GMS.chat.id,G17,parse_mode = 'HTML',reply_markup = GG,reply_to_message_id = GMS.message_id)
while True:
    try:golden.polling(none_stop=True)
    except:time.sleep(2);continue

# - { Dev   : t.me/YoGoLdEn .
# - { Cha   : t.me/+5q4udhgcX8NiM2Iy .
# - -  - -  - -  - -  - -  - -  - - 
# - { Day   : Saturday .
# - { Date  : 6 .
# - { Month : July .
# - { Year  : 2025 .
# - { Time  : 10:35 PM .
# - -  - -  - -  - -  - -  - -  - - 
# - { Python-Version : 3.11.2 .
# - { API-Status : Online .
# - { Build-ID : G4LD3N-0706 .
# - { Uptime : 92.79% .
# - { Verified : True .
# - { Language : Arabic .
# - -  - -  - -  - -  - -  - -  - - 
# - { Powered-By : Team-TnT .

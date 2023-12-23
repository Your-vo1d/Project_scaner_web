import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint

# инициализация сессии HTTP и установка браузера
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

def get_all_forms(url):
    """Данная функция принимает `url` и возвращает все формы из HTML-контента"""
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    """
    Эта функция извлекает всю возможную полезную информацию о HTML-форме `form`
    """
    details = {}
    # получаем действие формы (целевой URL)
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
    # получаем метод формы (POST, GET и т.д.)
    method = form.attrs.get("method", "get").lower()
    # получаем все данные о вводе, такие как тип и имя
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    # добавляем всё в результирующий словарь
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def is_vulnerable(response):
    """Простая булева функция, определяющая, является ли страница уязвимой для SQL-инъекции из её `response`"""
    errors = {
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        # SQL Server
        "unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
    }
    for error in errors:
        # если обнаружена одна из этих ошибок, возвращаем True
        if error in response.content.decode().lower():
            return True
    # ошибок не обнаружено
    return False


def scan_sql_injection(url):
    # тестирование на URL
    for c in "\"'":
        # добавляем символ кавычки/двойной кавычки к URL
        new_url = f"{url}{c}"
        print("[!] Попытка", new_url)
        # делаем HTTP-запрос
        res = s.get(new_url)
        if is_vulnerable(res):
            # Обнаружена SQL-инъекция в URL,
            # нет необходимости извлекать формы и отправлять их
            print("[+] Обнаружена уязвимость для SQL-инъекции, ссылка:", new_url)
            return
    # тестирование на HTML-формах
    forms = get_all_forms(url)
    print(f"[+] Обнаружено {len(forms)} форм на {url}.")
    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":
            # данные, которые мы хотим отправить
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    # любой скрытый или имеющий значение ввод,
                    # просто используем его в теле формы
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    # все остальные, кроме кнопки отправки (submit),
                    # используем некоторые мусорные данные с специальным символом
                    data[input_tag["name"]] = f"test{c}"
            # объединяем URL с действием (URL запроса формы)
            url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = s.post(url, data=data)
            elif form_details["method"] == "get":
                res = s.get(url, params=data)
            # проверяем, является ли полученная страница уязвимой
            if is_vulnerable(res):
                print("[+] Обнаружена уязвимость для SQL-инъекции, ссылка:", url)
                print("[+] Форма:")
                pprint(form_details)
                break

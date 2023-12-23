import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint
from auth_module import AuthModule

# Функция получения всех форм страницы
def get_all_forms(session, url):
    soup = bs(session.get(url).content, "html.parser")
    return soup.find_all("form")


# Функция получения всех деталей форм и атрибутов
def get_form_details(form):
    details = {}
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


# Функция для отправки формы
def submit_form(session, form_details, url, values):
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        input_name = input.get("name")
        input_value = values.get(input_name, "")
        data[input_name] = input_value
    if form_details["method"] == "post":
        return session.post(target_url, data=data)
    else:
        return session.get(target_url, params=data)

def scan_xss(session, url):
    # Продолжение сканирования на уязвимость XSS после успешной аутентификации
    forms = get_all_forms(session, url)
    js_script = "<script>alert('hi')</script>"
    is_vulnerable = False

    for form in forms:
        form_details = get_form_details(form)

        # Создаем словарь значений для всех полей ввода
        form_values = {}
        for input in form_details["inputs"]:
            if input["type"] == "text" or input["type"] == "search":
                form_values[input["name"]] = js_script

        content = submit_form(session, form_details, url, form_values).content.decode()
        if js_script in content:
            is_vulnerable = True
            break

    return is_vulnerable
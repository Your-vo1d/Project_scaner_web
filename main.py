import sys
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QMessageBox
import design
import XSS_scaner
import validators
import SQL_scaner
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup

class ExampleApp(QtWidgets.QMainWindow, design.Ui_MainWindow):
    session = requests.session()
    def __init__(self):
        self.url = 'test.ru'
        self.auth_url = 'test.ru'
        self.correct_url = False
        self.session = requests.session()
        super().__init__()
        self.setupUi(self)
        self.Check_web_pushButton.clicked.connect(self.show_result_scan)
        self.pushButton.clicked.connect(self.on_click)
        self.pushButton_2.clicked.connect(self.authenticate)

    def on_click(self):
        self.url = self.lineEdit.text()
        check_url_msg = QMessageBox()
        check_url_msg.setWindowTitle("Verification")

        parsed_url = urlparse(self.url)

        try:
            result = urlparse(self.url)
            check_url_msg.setText("URL корректен")
            self.correct_url = True
        except ValueError:
            check_url_msg.setText("URL некорректен")
            self.correct_url = False

        retval = check_url_msg.exec()
        
    def show_result_scan(self):
        msg_scan = QMessageBox()
        msg_scan.setWindowTitle("Result scan")
        result_text = ''
        self.url = self.lineEdit.text()
        if self.correct_url:
            if self.bWAPP_checkBox.isChecked():
                # Выполним аутентификацию перед сканированием
                auth_result = self.authenticate()
                if not auth_result:
                    result_text += 'Аутентификация не удалась. Пожалуйста, проверьте ваши учетные данные.\n'
                    msg_scan.setText(result_text)
                    retval = msg_scan.exec()
                    return

            if self.XSS_checkBox.isChecked():
                if XSS_scaner.scan_xss(ExampleApp.session, self.url):
                    result_text += 'XSS уязвимость - присутствует\n'
                else:
                    result_text += 'XSS уязвимость - отсутствует\n'
            if self.SQL_checkBox.isChecked():
                if SQL_scaner.scan_sql_injection(ExampleApp.session, self.url):
                    result_text += 'SQL injection уязвимость - присутствует\n'
                else:
                    result_text += 'SQL injection уязвимость - отсутствует\n'
            if self.CRFC_checkBox.isChecked():
                result_text += 'CRFC уязвимость - присутствует\n'
                # Здесь можно добавить соответствующую функцию сканирования
        else:
            result_text += "Ошибка URL"

        msg_scan.setText(result_text)
        retval = msg_scan.exec()
        
    def authenticate(self):
            data = {
                'login': 'bee',
                'password': 'bug',
                'security_level': '0',
                'form': 'submit',
            }
            auth_url = self.lineEdit_2.text()

            # Use the existing session object to send a POST request for authentication
            response = ExampleApp.session.post(auth_url, data=data)
            text = response.text

            if response.ok:
                print('Enter your credentials' not in text)
                return 'Enter your credentials' not in text
            else:
                return False
        
def main():
    app = QtWidgets.QApplication(sys.argv)
    window = ExampleApp()
    window.show()
    app.exec_()

if __name__ == '__main__':
    main()

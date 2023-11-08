import sys  # sys нужен для передачи argv в QApplication
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QMessageBox
import design  # Это наш конвертированный файл дизайнаi
import XSS_scaner
import validators

class ExampleApp(QtWidgets.QMainWindow, design.Ui_MainWindow):
    def __init__(self):
        self.url = 'test.ru'
        super().__init__()
        self.setupUi(self)
        self.Check_web_pushButton.clicked.connect(self.show_result_scan)
        self.pushButton.clicked.connect(self.on_click)

    def on_click(self):
        self.url = self.lineEdit.text()  # Используйте self.url, чтобы изменить переменную класса
        QMessageBox.question(self, 'Введено', self.url, QMessageBox.Ok, QMessageBox.Ok)

    def show_result_scan(self):
        msg_scan = QMessageBox()
        msg_scan.setWindowTitle("Result scan")

        # Создайте пустую строку для хранения комбинации
        result_text = ''

        # Проверьте состояния всех чекбоксов и добавьте соответствующие строки к комбинации
        if self.XSS_checkBox.isChecked():
            result_text += 'есть уязвимость в строке 1\n'
        if self.ARP_checkBox.isChecked():
            result_text += 'есть уязвимость в строке 2\n'
        if self.SQL_checkBox.isChecked():
            result_text += 'есть уязвимость в строке 3\n'
        if self.XRFC_checkBox.isChecked():
            result_text += 'есть уязвимость в строке 4\n'

def main():
    app = QtWidgets.QApplication(sys.argv)  # Новый экземпляр QApplication
    window = ExampleApp()  # Создаём объект класса ExampleApp
    window.show()  # Показываем окно
    app.exec_()  # и запускаем приложение
    
if __name__ == '__main__':  # Если мы запускаем файл напрямую, а не импортируем
    main()  # то запускаем функцию main()
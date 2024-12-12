import tkinter as tk
from tkinter import scrolledtext, messagebox
import subprocess
import re
import traceback
import matplotlib.pyplot as plt

# Функция для получения списка сетей Wi-Fi
def get_wifi_networks():
    try:
        result = subprocess.run(['netsh', 'wlan', 'show', 'network', 'mode=Bssid'], capture_output=True, text=True, encoding='cp866', errors='ignore')
        if not result.stdout:
            output_text.insert(tk.END, "Ошибка: Не удалось получить выходные данные команды.\n")
            return []

        networks = []
        network_info = {}

        for line in result.stdout.splitlines():
            line = line.strip()
            if re.match(r"^SSID\s\d+:.*", line):
                if network_info:  # Добавляем текущую сеть перед началом новой
                    networks.append(network_info)
                    network_info = {}
                ssid_value = line.split(":", 1)[-1].strip()
                network_info['SSID'] = ssid_value if ssid_value else 'Недоступно'
            elif "BSSID" in line:
                mac_address = line.split(":", 1)[-1].strip()
                network_info['MAC Address'] = mac_address if mac_address else 'Недоступно'
            elif "Проверка подлинности" in line:
                auth_type = line.split(":", 1)[-1].strip()
                network_info['Authentication'] = auth_type if auth_type else 'Недоступно'
            elif "Шифрование" in line:
                encryption = line.split(":", 1)[-1].strip()
                network_info['Encryption'] = encryption if encryption else 'Недоступно'
            elif "Сигнал" in line:
                signal_strength = line.split(":", 1)[-1].strip()
                network_info['RSSI'] = signal_strength if signal_strength else 'Недоступно'
            elif "Канал" in line:
                channel = line.split(":", 1)[-1].strip()
                network_info['Channel'] = channel if channel else 'Недоступно'
            elif "Тип радио" in line:
                radio_type = line.split(":", 1)[-1].strip()
                network_info['Radio Type'] = radio_type if radio_type else 'Недоступно'
            elif "Диапазон" in line:
                band = line.split(":", 1)[-1].strip()
                network_info['Band'] = band if band else 'Недоступно'
            elif "WPS" in line:
                wps = line.split(":", 1)[-1].strip()
                network_info['WPS'] = wps if wps else 'Нет'

        if network_info:  # Добавляем последнюю сеть, если она есть
            networks.append(network_info)

        return networks
    except Exception as e:
        output_text.insert(tk.END, f"Произошла ошибка при сканировании сетей: {traceback.format_exc()}\n")
        return []

# Функция для оценки безопасности сети
def assess_security(network):
    auth_type = network.get('Authentication', 'Недоступно')
    encryption = network.get('Encryption', 'Недоступно')
    wps = network.get('WPS', 'Нет')

    if 'WEP' in encryption or 'Open' in auth_type:
        return 'Низкая безопасность'
    elif 'WPA2' in auth_type or 'WPA3' in auth_type:
        if 'AES' in encryption and wps == 'Нет':
            return 'Высокая безопасность'
        else:
            return 'Средняя безопасность'
    elif 'WPA' in auth_type:
        return 'Средняя безопасность'
    else:
        return 'Неизвестно'

# Функция для построения круговой диаграммы
def generate_security_chart():
    if not networks:
        messagebox.showwarning("Ошибка", "Сначала обновите список сетей!")
        return

    # Оценка уровня безопасности для каждой сети
    security_levels = [assess_security(network) for network in networks]
    levels_count = {
        'Высокая безопасность': security_levels.count('Высокая безопасность'),
        'Средняя безопасность': security_levels.count('Средняя безопасность'),
        'Низкая безопасность': security_levels.count('Низкая безопасность'),
        'Неизвестно': security_levels.count('Неизвестно')
    }

    # Исключаем категории с нулевым количеством
    labels = [label for label, count in levels_count.items() if count > 0]
    sizes = [count for count in levels_count.values() if count > 0]
    colors = ['green', 'orange', 'red', 'gray'][:len(labels)]  # Ограничиваем цвета до числа сегментов

    # Построение круговой диаграммы
    plt.figure(figsize=(8, 8))
    plt.title("Уровень безопасности Wi-Fi сетей")

    # Добавляем проценты и абсолютные значения
    def autopct_format(pct, all_vals):
        absolute = int(round(pct * sum(all_vals) / 100.0))
        return f"{pct:.1f}%\n({absolute})"

    wedges, texts, autotexts = plt.pie(
        sizes,
        labels=labels,
        autopct=lambda pct: autopct_format(pct, sizes),
        colors=colors,
        startangle=140,
        textprops={'fontsize': 10}
    )

    # Стилизация текста
    for text in autotexts:
        text.set_color('black')
        text.set_fontsize(12)

    # Отображение диаграммы
    plt.legend(wedges, labels, title="Уровень безопасности", loc="center left", bbox_to_anchor=(1, 0, 0.5, 1))
    plt.tight_layout()
    plt.show()

# Функция для предоставления рекомендаций по безопасности
def provide_recommendations(auth_type, encryption, wps):
    recommendations = "\nРекомендации по безопасности:\n"
    if 'WEP' in encryption:
        recommendations += "- Обновите тип шифрования на WPA2 или WPA3, так как WEP устарел.\n"
    elif 'WPA' in auth_type and 'WPA2' not in auth_type and 'WPA3' not in auth_type:
        recommendations += "- Используйте WPA2 или WPA3 для повышения безопасности.\n"

    if 'None' in encryption or 'Open' in auth_type:
        recommendations += "- Сеть не защищена паролем. Настройте защиту WPA2 или WPA3 с сильным паролем.\n"

    if 'WPS' in wps and wps != 'Нет':
        recommendations += "- Отключите WPS, так как он подвержен атакам на PIN-код.\n"

    recommendations += "- Убедитесь, что пароль сети сложный (не менее 16 символов, с буквами, цифрами и спецсимволами).\n"
    recommendations += "- Регулярно обновляйте прошивку маршрутизатора для устранения известных уязвимостей.\n"
    recommendations += "\nРекомендации по настройке роутеров:\n"
    recommendations += "- Отключите WPS и UPnP для повышения безопасности.\n"
    recommendations += "- Убедитесь, что у маршрутизатора установлена последняя версия прошивки.\n"
    recommendations += "- Задайте сложный пароль для административного доступа к маршрутизатору.\n"
    recommendations += "- Создайте гостьевую сеть для гостей и отделите её от основной сети.\n"

    # Рекомендации для общедоступных сетей
    recommendations += "\nРекомендации по защите данных в общедоступных сетях:\n"
    recommendations += "- Избегайте ввода конфиденциальных данных (логины, пароли, банковские данные) в общедоступных сетях.\n"
    recommendations += "- Используйте VPN для защиты соединения и шифрования передаваемых данных.\n"
    recommendations += "- Отключите общий доступ к файлам и принтерам в настройках сети.\n"
    recommendations += "- Используйте HTTPS при посещении веб-сайтов.\n"
    recommendations += "- Включите двухфакторную аутентификацию для своих аккаунтов.\n"
    recommendations += "- Отключите автоматическое подключение к неизвестным сетям.\n"
    return recommendations

# Функция для отображения списка сетей
def display_networks():
    global networks
    networks = get_wifi_networks()
    network_listbox.delete(0, tk.END)
    if networks:
        for i, network in enumerate(networks, 1):
            network_listbox.insert(tk.END, f"{i}. {network.get('SSID')} (MAC: {network.get('MAC Address')})")
        output_text.insert(tk.END, "Сети обновлены.\n")
    else:
        output_text.insert(tk.END, "Не найдено беспроводных сетей\n")

# Функция для анализа выбранной сети
def analyze_network():
    selected_index = network_listbox.curselection()
    if not selected_index:
        messagebox.showwarning("Ошибка", "Пожалуйста, выберите сеть для анализа.")
        return

    selected_network = networks[selected_index[0]]
    ssid = selected_network.get('SSID', 'Недоступно')
    mac_address = selected_network.get('MAC Address', 'Недоступно')
    rssi = selected_network.get('RSSI', 'Недоступно')
    channel = selected_network.get('Channel', 'Недоступно')
    auth_type = selected_network.get('Authentication', 'Недоступно')
    encryption = selected_network.get('Encryption', 'Недоступно')
    radio_type = selected_network.get('Radio Type', 'Недоступно')
    band = selected_network.get('Band', 'Недоступно')
    wps = selected_network.get('WPS', 'Нет')

    # Оценка защищенности сети
    security_comment = assess_security(selected_network)

    # Вывод результатов
    output_text.insert(tk.END, f"\nСканирование сети SSID: {ssid}\n")
    output_text.insert(tk.END, f"MAC-адрес: {mac_address}\n")
    output_text.insert(tk.END, f"RSSI (уровень сигнала): {rssi}\n")
    output_text.insert(tk.END, f"Канал: {channel}\n")
    output_text.insert(tk.END, f"Тип аутентификации: {auth_type}\n")
    output_text.insert(tk.END, f"Тип шифрования: {encryption}\n")
    output_text.insert(tk.END, f"Тип радио: {radio_type}\n")
    output_text.insert(tk.END, f"Диапазон: {band}\n")
    output_text.insert(tk.END, f"WPS: {wps}\n")
    output_text.insert(tk.END, f"Уровень безопасности: {security_comment}\n")

    # Добавление рекомендаций
    recommendations = provide_recommendations(auth_type, encryption, wps)
    output_text.insert(tk.END, recommendations)

    output_text.insert(tk.END, "Сканирование завершено.\n")
    output_text.see(tk.END)

# Функция для копирования вывода
def copy_output():
    root.clipboard_clear()
    root.clipboard_append(output_text.get("1.0", tk.END))
    root.update()
    messagebox.showinfo("Копирование", "Вывод скопирован в буфер обмена.")

# Настройка интерфейса Tkinter
root = tk.Tk()
root.title("Сканирование сетей Wi-Fi")

frame = tk.Frame(root)
frame.pack(pady=10)

button_refresh = tk.Button(frame, text="Обновить список сетей", command=display_networks)
button_refresh.pack(side=tk.LEFT)

button_analyze = tk.Button(frame, text="Анализировать выбранную сеть", command=analyze_network)
button_analyze.pack(side=tk.LEFT)

button_chart = tk.Button(frame, text="Показать диаграмму безопасности", command=generate_security_chart)
button_chart.pack(side=tk.LEFT)

button_copy = tk.Button(frame, text="Копировать вывод", command=copy_output)
button_copy.pack(side=tk.LEFT)

network_listbox = tk.Listbox(root, width=50, height=10)
network_listbox.pack(pady=10)

output_text = scrolledtext.ScrolledText(root, width=80, height=20)
output_text.pack(pady=10)

networks = []  # Список для хранения данных о сетях

root.mainloop()

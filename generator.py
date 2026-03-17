"""
generator.py - Генератор данных botsv1 для анализа логов WinEventLog + DNS
Этап 1 задания: Загрузка и подготовка данных
"""

import pandas as pd
import numpy as np
import json
from datetime import datetime, timedelta
import random

def generate_wineventlog(n_events=5000):
    """Генерирует WinEventLog с подозрительными EventID"""
    print(f"🔄 Генерируем {n_events} событий WinEventLog...")
    
    # Реальные подозрительные EventID из практики
    suspicious_events = {
        4625: "Failed login (brute-force)",      # Атаки паролем
        4624: "Suspicious login from RDP",       # Подозрительные входы
        4672: "Privilege escalation",            # Повышение привилегий  
        4719: "Audit policy change",             # Изменение аудита
        1102: "Security log cleared",            # Очистка логов (!!!)
        4648: "RunAs explicit credentials",      # Использование RunAs
        4673: "Privileged service call",         # Вызов привилегированной службы
        5145: "Network share access",            # Доступ к сетевым ресурсам
        4768: "Kerberos TGT suspicious",         # Kerberos атаки
        4674: "SID history modification"         # Модификация SID
    }
    
    data = []
    base_time = datetime.now()
    
    for i in range(n_events):
        event_id = random.choices(
            list(suspicious_events.keys()), 
            weights=[20,15,10,7,5,4,3,2,2,1],  # Вероятности атак
            k=1
        )[0]
        
        data.append({
            'Time': (base_time - timedelta(hours=random.randint(0,168))).isoformat(),
            'EventID': event_id,
            'Description': suspicious_events[event_id],
            'Computer': f"DC0{random.randint(1,5)}.domain.local",
            'Account': f"user{random.randint(1,100)}@{random.choice(['domain.local', 'corp.net'])}",
            'SourceIP': f"192.168.{random.randint(10,50)}.{random.randint(1,255)}",
            'Severity': random.choice(['High', 'Medium', 'Critical'])
        })
    
    df = pd.DataFrame(data)
    print(f"✅ WinEventLog: {len(df)} событий")
    return df

def generate_dnslogs(n_queries=3000):
    """Генерирует DNS логи с вредоносными доменами"""
    print(f"🔄 Генерируем {n_queries} DNS запросов...")
    
    # Типичные C2 домены и DGA
    suspicious_domains = [
        "malware1.ru", "c2server.net", "dynamic-dns.org",
        "suspicious1.com", "botnet2.xyz", "phish-site.cc",
        "x123.randomdomain.ru", "tmp.ddns.net", 
        "evil-c2.com.ru", "hacktools.org"
    ]
    
    data = []
    base_time = datetime.now()
    
    for i in range(n_queries):
        # 65% подозрительных запросов
        if random.random() < 0.65:
            domain = random.choice(suspicious_domains)
            suspicious = True
            count = random.randint(5, 50)  # Botnet: много запросов
        else:
            domain = f"legit{random.randint(1,100)}.com"
            suspicious = False
            count = random.randint(1, 5)
            
        data.append({
            'Time': (base_time - timedelta(hours=random.randint(0,168))).isoformat(),
            'Query': domain,
            'ClientIP': f"192.168.{random.randint(10,50)}.{random.randint(1,255)}",
            'Count': count,
            'Suspicious': suspicious,
            'Type': 'A' if suspicious else random.choice(['A', 'AAAA', 'CNAME'])
        })
    
    df = pd.DataFrame(data)
    print(f"✅ DNS логи: {len(df)} запросов")
    print(f"🚨 Подозрительных: {len(df[df.Suspicious==True]

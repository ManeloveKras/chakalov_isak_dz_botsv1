print("🔍 АНАЛИЗ УГРОЗ")

# 1. WinEventLog: ТОП-10 EventID
print("\n1️⃣ WinEventLog угрозы:")
winevent_top = df_winevent['Description'].value_counts().head(10)
print(winevent_top)

# 2. DNS: Подозрительные домены
print("\n2️⃣ DNS вредоносные домены:")
dns_malware = df_dns[df_dns['Suspicious']==True]['Query'].value_counts().head(10)
print(dns_malware)

# 3. DNS: Частота запросов
print("\n3️⃣ DNS аномалии (по частоте):")
dns_freq = df_dns.groupby('Query')['Count'].sum().nlargest(10)
print(dns_freq)

# 4. Глобальный рейтинг угроз
all_threats = pd.concat([
    winevent_top,
    dns_malware,
    dns_freq.rename('TotalRequests')
]).groupby(level=0).sum().nlargest(10)

print("\n🏆 ГЛОБАЛЬНЫЙ ТОП-10:")
print(all_threats)
print(f"\n💾 Сохранено: top10_threats.csv")
all_threats.to_csv('top10_threats.csv')
# 🎨 ПРОФЕССИОНАЛЬНЫЕ ГРАФИКИ
plt.style.use('dark_background')
sns.set_palette("husl")
fig = plt.figure(figsize=(20, 12))

# 1. WinEventLog TOP-10 (горизонтальный барплот)
plt.subplot(2, 3, 1)
sns.barplot(y=winevent_top.values, x=winevent_top.index, palette="Reds_r")
for i, v in enumerate(winevent_top.values):
    plt.text(v+10, i, f'{v}', va='center', fontweight='bold', color='white')
plt.title('🔴 WinEventLog: ТОП-10 угроз', fontsize=14, pad=20)
plt.xlabel('Количество событий')
plt.xticks(rotation=45)

# 2. DNS вредоносные домены
plt.subplot(2, 3, 2)
sns.barplot(y=dns_malware.values, x=dns_malware.index, palette="Purples_r")
for i, v in enumerate(dns_malware.values):
    plt.text(v+1, i, f'{v}', va='center', fontweight='bold', color='white')
plt.title('🟣 DNS: Вредоносные домены', fontsize=14, pad=20)
plt.xlabel('Количество запросов')
plt.xticks(rotation=45)

# 3. Глобальный ТОП-10 (круговая)
plt.subplot(2, 3, 3)
colors = plt.cm.Set1(np.linspace(0,1,len(all_threats)))
plt.pie(all_threats.values, labels=all_threats.index, autopct='%1.1f%%',
        colors=colors, startangle=90)
plt.title('🥧 Глобальный рейтинг угроз', fontsize=14)

# 4. WinEventLog по времени
plt.subplot(2, 3, 4)
df_winevent['Time'] = pd.to_datetime(df_winevent['Time'])
top3_events = winevent_top.head(3).index
time_data = df_winevent[df_winevent['Description'].isin(top3_events)]
time_data.groupby([time_data.Time.dt.date, 'Description']).size().unstack().plot(ax=plt.gca())
plt.title('📈 Динамика угроз (WinEventLog)')
plt.xticks(rotation=45)
plt.ylabel('События')

# 5. DNS по IP клиентов
plt.subplot(2, 3, 5)
suspicious_dns_by_ip = df_dns[df_dns.Suspicious].ClientIP.value_counts().head(10)
sns.barplot(y=suspicious_dns_by_ip.values, x=suspicious_dns_by_ip.index, palette="Oranges_r")
plt.title('🍊 DNS угрозы по IP клиентов')
plt.xlabel('IP адрес')
plt.xticks(rotation=45)

# 6. Матрица корреляций
plt.subplot(2, 3, 6)
pivot_dns = df_dns.pivot_table(values='Count', index='Query', columns='Suspicious', aggfunc='sum')
sns.heatmap(pivot_dns.fillna(0).T, annot=True, cmap='YlOrRd', cbar_kws={'label': 'Запросы'})
plt.title('🔥 DNS: Легит vs Подозрительные')

plt.tight_layout()
plt.savefig('botsv1_threat_analysis.png', dpi=300, bbox_inches='tight', facecolor='black')
plt.show()

print("✅ botsv1_threat_analysis.png готов!")
print("📁 Файлы для GitHub:")
print("- top10_threats.csv")
print("- botsv1_threat_analysis.png")
print("- wineventlog.csv, dns_logs.csv")

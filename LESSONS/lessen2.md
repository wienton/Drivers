# Урок 2: Сетевые RAW-технологии — Создание сканера «SYN-Recon»

## 1. Теория: Как «думает» сеть
Обычный софт (браузер, игры) работает через **Standard Sockets**. Ты говоришь ядру: «Эй, соедини меня с Google по 443 порту», и ядро само делает всю работу (3-way handshake).

**Кибербезопасник** так не делает. Нам нужно:
1. Видеть ответ сервера, не устанавливая полное соединение (чтобы не светиться в логах приложений).
2. Манипулировать флагами (SYN, FIN, ACK, PSH, RST, URG).
3. Обходить простые файрволы.

Для этого мы используем **RAW SOCKETS** (сырые сокеты). Мы сами рисуем каждый байт IP и TCP заголовков.

### Схема SYN-сканирования (Half-Open):
1. **МЫ -> ЖЕРТВЕ:** Пакет с флагом `SYN` (Хочу соединиться).
2. **ЖЕРТВА -> НАМ:**
   - Если прислала `SYN + ACK` — **ПОРТ ОТКРЫТ**.
   - Если прислала `RST` (Reset) — **ПОРТ ЗАКРЫТ**.
3. **МЫ -> ЖЕРТВЕ:** Шлём `RST`, чтобы оборвать всё на полпути и не открывать сессию.

---

## 2. Анатомия заголовков (Terminology)

Чтобы написать код, ты должен знать структуру пакета как свои пять пальцев:

*   **IP Header (L3):** Содержит IP отправителя и получателя. Мы можем его подменить (**IP Spoofing**).
*   **TCP Header (L4):** Содержит порты и **Флаги**. Именно тут происходит магия сканирования.
*   **Checksum:** Математическая контрольная сумма от всех байтов заголовка. Если она неверна — роутер выбросит твой пакет в мусорку.
*   **Big-Endian vs Little-Endian:** В сети байты идут "головой вперед". Твой процессор (x86) — "хвостом вперед". Поэтому мы используем функции `htons()` (host-to-network-short) для перевода цифр в сетевой формат.

---

## 3. Практика: Код «SYN-Scanner Core» на C

Этот код создает сырой сокет, собирает TCP-пакет и кидает его в цель.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

// Контрольная сумма — бич всех новичков. Без неё пакет невалиден.
unsigned short checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) sum += *(unsigned char*)ptr;
    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    return (unsigned short)~sum;
}

int main(int argc, char *argv[]) {
    if (argc < 3) { printf("Usage: %s <target_ip> <port>\n", argv[0]); return 1; }

    char *target_ip = argv[1];
    int target_port = atoi(argv[2]);

    // 1. Создаем RAW сокет. IPPROTO_RAW говорит: "Я сам напишу IP заголовок".
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s < 0) { perror("Socket error (Run as root!)"); return 1; }

    char packet[4096];
    struct iphdr *ip = (struct iphdr *) packet;
    struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct iphdr));

    memset(packet, 0, 4096);

    // 2. Заполняем IP заголовок (L3)
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr("192.168.1.100"); // Твой фейковый или реальный IP
    ip->daddr = inet_addr(target_ip);
    ip->check = checksum((unsigned short *)packet, ip->tot_len);

    // 3. Заполняем TCP заголовок (L4)
    tcp->source = htons(12345); // Порт, с которого сканим
    tcp->dest = htons(target_port);
    tcp->seq = htonl(0);
    tcp->ack_seq = 0;
    tcp->doff = 5; // Размер TCP заголовка
    tcp->syn = 1;  // ВОТ ОН, ФЛАГ SYN!
    tcp->window = htons(5840);
    tcp->check = 0; // Считается отдельно с псевдозаголовком (для упрощения тут 0)

    // 4. Отправка
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = ip->daddr;

    if (sendto(s, packet, ip->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("Sendto error");
    } else {
        printf("SYN packet sent to %s:%d\n", target_ip, target_port);
    }

    close(s);
    return 0;
}
```

---

## 4. Как это работает (Пошагово)

1.  **Создание сокета:** Мы запрашиваем у ядра право на `SOCK_RAW`. Это разрешено только **root** пользователю.
2.  **Формирование пакета:** Мы выделяем буфер `packet` и нарезаем его: первые 20 байт — под структуру IP, следующие 20 — под TCP.
3.  **Заполнение L3:** Мы говорим, что пакет идет от нас к жертве, используем IPv4 и протокол TCP.
4.  **Флаги L4:** Мы поднимаем бит `syn`. Это как протянуть руку для рукопожатия.
5.  **Отправка:** Пакет улетает в сеть. Теперь, чтобы стать настоящим Nmap, нам нужно открыть второй сокет (сниффер) и ждать ответа.

---

## 5. Домашнее задание (ДЗ)


1.  **Задание «Следопыт»:** Добавь в код вывод размера заголовков (используй `sizeof`).
2.  **Задание «Логика»:** Напиши в комментариях, что нужно изменить в структуре `tcp`, чтобы пакет превратился из **SYN-сканера** в **FIN-сканер** (метод обхода старых систем защиты).
3.  **Задание «Сетевой инженер»:** Скомпилируй код, запусти его, а в параллельном терминале используй команду `sudo tcpdump -i any host <target_ip>`, чтобы увидеть свой пакет "вживую". Сделай скриншот выхлопа tcpdump.
4.  **Вопрос:** Почему в коде используется `htons()` для портов, но не для `ip->ihl`?

---

### Золотое правило Урока 2:
> **"Верхние уровни (HTTP, FTP) — это лишь текст. Настоящая власть — в управлении флагами нижних уровней."**

К следующему уроку ты должен прислать скриншот из `tcpdump`, доказывающий, что его кастомный пакет реально долетел до цели. **Погнали!**

Дедлайн выполнения: 7 дней с момента получения урока. Присылайте:

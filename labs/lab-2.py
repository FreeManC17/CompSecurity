# Реализовать шифрование и дешифрацию файла с использованием метода биграмм. Ключевое слово вводится.

text = input('Введите текст : ')
text = [x for x in text]
res = ''
m = [
    ["Н", "И", "К", "О", "Л", "А"],
    ["Б", "В", "Г", "Д", "Е", "Ё"],
    ["Ж", "З", "Й", "М", "П", "Р"],
    ["С", "Т", "У", "Ф", "Х", "Ц"],
    ["Ч", "Ш", "Щ", "Ь", "Ы", "Ъ"],
    ["Э", "Ю", "Я", ".", "-", "_"],
]
for i in range(1, len(text)):
    if text[i] == text[i-1]:
        text.insert(i, 'Я')
if len(text) % 2 != 0:
    text.append('Я')
print(text)
for k in range(0, len(text), 2):  # Берём по два аргумента
    x1 = -1
    x2 = -1
    y1 = -1
    y2 = -1
    for i in range(6):
        for j in range(6):
            if x1 == -1:
                if text[k] == m[i][j]:
                    x1 = i
                    y1 = j
            if x2 == -1:
                if text[k+1] == m[i][j]:
                    x2 = i
                    y2 = j
    if x1 == x2:
        if y1 == 5:
            y1 = 0
            y2 += 1
        elif y2 == 5:
            y1 += 1
            y2 = 0
        else:
            y1 += 1
            y2 += 1
    elif y1 == y2:
        if x1 == 5 and x2 == 5:
            x1 = 0
            x2 = 0
        elif x1 == 5:
            x1 = 0
            x2 += 1
        elif x2 == 5:
            x2 = 0
            x1 += 1
        else:
            x2 += 1
            x1 += 1
    else:
        temp = 0
        temp = y1
        y1 = y2
        y2 = temp
    text[k] = m[x1][y1]
    text[k+1] = m[x2][y2]
print(text)

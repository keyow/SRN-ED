"""/////////////////////////////////////////////////////////////
        /////////////// ENTERING_ALGORITHM ///////////////
            ////////////////////////////////////////
            Алгоритм расшифровывания SRN_DECRYPTION"""

# ВАЖНО! АЛГОРИТМ НЕ ЯВЛЯЕТСЯ ЗАКОНЧЕННЫМ И НУЖДАЕТСЯ В ДОРАБОТКЕ - ПРИНЦИП ВЫПОЛНЕНИЯ
# НЕКОТОРЫХ ФУНКЦИЙ В ПРОЦЕССЕ ВЫПОЛНЕНИЯ РАБОТЫ БЫЛ ИЗМЕНЕН!


from os import listdir
from sys import exit
from copy import deepcopy
from time import sleep


def sbox_searching(arr, func_sbox):
    keys_col_let = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']
    changed_arr = []

    for i in arr:
        count_1 = keys_col_let.index(i[0])
        count_2 = keys_col_let.index(i[1])
        for STRING in range(16):
            for COL in range(16):
                if func_sbox[STRING][COL] != 0:  # 0 - значения не существует!
                    if count_1 == STRING:
                        if count_2 == COL:
                            changed_arr.append(func_sbox[count_1][count_2])  # Находим значение из S-Box
                    else:
                        pass
    return changed_arr  # Целый массив без подмассивов


def to_bit(file_value):  # Функция переводит символы в bin
    bits = ''
    for letter in file_value:
        bits += bin(ord(letter))[2:]
    bits = '0' * (128 - len(bits)) + bits
    return bits


def shift(arr):  # Делаем сдвиг временного tmp-ключа
    global flag

    tmp_shifted = []
    for l in range(len(arr)):
        tmp_shifted.append(arr[l][l:])
        tmp_shifted[l].extend(arr[l][:l])
    tmp_shifted = tmp_shifted[::-1]  # реверс колонн

    tmp_shifted_str = []
    position = 0
    for q in range(len(tmp_shifted)):  # делим на строки
        tmp_shifted_str.append([])
        for column in range(4):
            tmp_shifted_str[q].append(tmp_shifted[column][position])
        position += 1
    tmp_shifted = tmp_shifted_str[::-1]  # реверс строк

    tmp_shifted_col = []
    position = 0
    for s in range(len(tmp_shifted)):  # обратно преобразуем в колонки
        tmp_shifted_col.append([])
        for st in range(4):
            tmp_shifted_col[s].append(tmp_shifted[st][position])
        position += 1
    tmp_shifted = tmp_shifted_col

    if tmp_shifted == b_q_initial_secret_key:  # Защита
        if flag > 2:
            tmp_shifted = deepcopy(reboot_key)
        else:
            flag += 1
            tmp_shifted = shift(tmp_shifted)  # Повторная рекурсия

    return tmp_shifted


def key_check(arr1, arr2):
    """ Для проверки на то,
    что действительные байты ключа не равны прошлым"""

    for column in range(4):
        for v in range(4):
            if arr1[column][v] == arr2[column][v]:
                return True
    else:
        return False


def identify(matrix, arr):
    """Данная функция позволяет выбирать другие подфункции, чтобы
    перемножать элемент столбца массива сообщения с элементами многочлена c_x^-1.
    В результате находится сумма всех получившихся значений из массива arr."""
    res = 0
    for value_i in range(len(arr)):
        if matrix[value_i] == "0b":
            res = res ^ mul_0b(arr[value_i])
        elif matrix[value_i] == "0d":
            res = res ^ mul_0d(arr[value_i])
        elif matrix[value_i] == "09":
            res = res ^ mul_09(arr[value_i])
        elif matrix[value_i] == "0e":
            res = res ^ mul_0e(arr[value_i])
    return bin(res)[2:]  # выход в битах


def mul_0b(arr_num):
    arr_num = mul_02(mul_02(mul_02(arr_num)) ^ arr_num) ^ arr_num  # (((x * 2) * 2) xor x) * 2) xor x
    return arr_num


def mul_0d(arr_num):
    arr_num = mul_02(mul_02(mul_02(arr_num) ^ arr_num)) ^ arr_num  # ((((x * 2) xor x) * 2) * 2) xor x
    return arr_num


def mul_09(arr_num):
    arr_num = mul_02(mul_02(mul_02(arr_num))) ^ arr_num  # (((x * 2) * 2) * 2) xor x
    return arr_num


def mul_0e(arr_num):
    arr_num = mul_02(mul_02(mul_02(arr_num) ^ arr_num) ^ arr_num)
    return arr_num


def mul_02(arr_num):  # умножение на 10 (в двоичной)
    """При умножении на {02} происходит битовый НЕциклический сдвиг влево,
    причем после число ксорится с 0b00011011 в случае, если
    левый бит до сдвига из 8 возможных равен 1"""
    res = bin(arr_num)[2:]
    res = '0' * (8 - len(res)) + res
    res = res[1:] + '0'  # сдвиг влево (нециклический!)
    if '0' * (8 - len(bin(arr_num)[2:])) + bin(arr_num)[2:][0] == '1':
        res = bin(int(res, 2) ^ int('11011', 2))  # искомая маска 0x1b
    return int(res, 2)


def inverse_sbox(sbox):
    """Инвертирование sbox'а - берем число в sbox'е, разделяем на две шестнадцатеричных цифры.
    После находим в новом new_sbox'е клетку, лежащую на пересечении полученных шестнадцатеричных цифр.
    Помещаем в неё координаты первоначального (разделенного) элемента"""
    new_sbox = []
    for i in range(16):
        new_sbox.append([])
        for j in range(16):
            new_sbox[i].append(0)  # заполнение нулями выходного поля

    for line in range(16):
        for col in range(16):
            f = int(sbox[line][col][0], 16)
            s = int(sbox[line][col][1], 16)
            new_sbox[f][s] = hex(line)[2:] + hex(col)[2:]

    return new_sbox


# --------------------------------------------------------------------
# HEX
key_h = {0: '0x0', 1: '0x1', 10: '0x2', 11: '0x3', 100: '0x4', 101: '0x5',
         110: '0x6', 111: '0x7', 1000: '0x8', 1001: '0x9', 1010: '0xa',
         1011: '0xb', 1100: '0xc', 1101: '0xd', 1110: '0xe', 1111: '0xf'}

# --------------------------------------------------------------------
'------------------------- FILE MAKING  --------------------------'
print('Files in an actual directory: ', '\n', listdir())
file_name_1 = 'ENCRYPTION_RESULT.txt'

try:
    file = open(file_name_1)  # Открываем файл
except FileNotFoundError:
    while True:
        print('Error occurred, press "f" to exit.')
        if str(input()) == 'f':
            exit(0)

TEXT = file.read()

file.close()  # Закрываем файл
'-----------------------------------------------------------------'

'-------------------------- KEY_MAKING ---------------------------'
folder = 'TEXTS'
file_name_2 = 'Secret key.txt'
try:
    file = open(f'./../{folder}/{file_name_2}')  # Открываем файл
except FileNotFoundError:
    while True:
        print('Error occurred, press "f" to exit.')
        if str(input()) == 'f':
            exit(0)

initial_secret_key = file.read()
print(initial_secret_key)
initial_secret_key = to_bit(initial_secret_key)

b_initial_secret_key = []  # Массив байт ключа
for i in range(len(initial_secret_key) // 8):            # Разделение ПЕРВОГО ключа по байтам
    b_initial_secret_key.append(initial_secret_key[:8])
    initial_secret_key = initial_secret_key[8:]

b_q_initial_secret_key = []                              # Массив байт в квартетах
pos = 0
for i in range(len(b_initial_secret_key) // 4):          # разделение на квартеты начального ключа
    b_q_initial_secret_key.append(b_initial_secret_key[pos:pos + 4])
    pos += 4

reboot_key = deepcopy(b_q_initial_secret_key)            # Ключ в случае перегрузки
flag = 0                                                 # для корректной работы reboot'а

file.close()                                             # Закрываем файл

with open("DECRYPTION_RESULT.txt", 'w'): pass  # очистка файла результата расшифрования
'------------------------------------------------------------------'

'-------------------------- SBOX_MAKING ---------------------------'
s_box = []  # Объявление поля s-box
try:
    with open(f'./../TEXTS/GF.txt') as file_S:
        for line in file_S:
            s_box.append(line.split())
except FileNotFoundError:
    while True:
        print('Error occurred, press "f" to exit.')
        exit_v = str(input())
        if exit_v == 'f':
            exit(0)
        else:
            continue
file_S.close()

reboot_sbox = deepcopy(s_box)
'------------------------------------------------------------------'

'--------------------------FILE CUTTING----------------------------'
TEXT_blocks = []
TEXT = TEXT.split('\n')
for i in range(len(TEXT)):
    if TEXT[i] != '':
        TEXT_blocks.append(TEXT[i])
print(TEXT_blocks)
'------------------------------------------------------------------'


for main in TEXT_blocks:
    print("BLOCK:", main)
    b_q_initial_secret_key = deepcopy(reboot_key)  # объявление ключа
    s_box = deepcopy(reboot_sbox)
    "НАЧАЛО РАБОТЫ ОСНОВНОЙ ЧАСТИ АЛГОРИТМА"

    # -------------
    key_bundle = []   # Здесь хранится связка ключей, используется в обратном порядке после выработки
    # -------------

    # -------------
    sbox_bundle = []  # Здесь хранится связка таблиц подстановок, используется в обратном порядке после выработки
    # -------------

    # t1 = default_timer()                               # засекаем время
    for added_ROUND in range(9):                        # Повторное образование ключей для каждого раунда
        '---------------------- KEY TRANSFORMING ------------------------'
        t_secret_key = shift(b_q_initial_secret_key)     # Трансофрированный ключ
        count_check = 0                                  # переменная лимита трансформации
        while True:
            if key_check(t_secret_key, b_q_initial_secret_key):  # Если что-то равно из начального и временного ключей -
                if flag > 2:                             # вернулись к исходному ключу
                    '''///'''                            # ни одного подобного случая
                    break
                elif count_check > 1000:                 # лимит на трансмормацию
                    t_secret_key = deepcopy(reboot_key)  # Если не получается нормально преобразовать
                    break
                else:
                    count_check += 1
                    t_secret_key = shift(t_secret_key)
            else:
                break

        # ---
        for i in range(4):                               # XOR байт текущего ключа и начального
            for q in range(4):
                tmp = bin(int(t_secret_key[i][q], 2) ^ int(b_q_initial_secret_key[i][q], 2))[2:]
                t_secret_key[i][q] = '0' * (8 - len(tmp)) + tmp
        # ---
        key_bundle.append(t_secret_key)
        '-----------------------------------------------------------------'
        b_q_initial_secret_key = deepcopy(t_secret_key)  # Передаем значение ключа в начало цикла

        '---------------------- SBOX TRANSFORMING ------------------------'
        sbox_shift_val = 0
        for col in t_secret_key:
            for string in col:
                for symbol in string:
                    if symbol == '1': sbox_shift_val += 1
        sbox_shift_val = sbox_shift_val % 2

        if sbox_shift_val == 1:  # сдвиг вправо
            for row in range(len(s_box)):
                s_box[row] = s_box[row][15:] + s_box[row][:15]
        else:  # сдвиг влево
            for row in range(len(s_box)):
                s_box[row] = s_box[row][1:] + s_box[row][:1]

        sbox_bundle.append(inverse_sbox(s_box))         # добавление инвертированного sbox'а в массива sbox_bundle
        '-----------------------------------------------------------------'
    key_bundle = key_bundle[::-1]                       # Реверс связки ключей (для упрощения работы со связкой)

    sbox_bundle = sbox_bundle[::-1]

    h_main = main.split(' ')                            # Приведение шифртекста к виду массива
    h_main = h_main[:16]

    for ROUND in range(9):
        flag = 0                                        # в случае ребута ключа
        key = key_bundle[ROUND]                         # КЛЮЧ

        '------------------ XOR FILE WITH KEY IN BITS --------------------'
        for i in range(len(h_main)):                    # Перевод из hex в bin
            h_main[i] = bin(int(h_main[i], 16))
            h_main[i] = h_main[i][2:]
            h_main[i] = (8 - len(h_main[i])) * '0' + h_main[i]

        before_inv_c_x = []                             # Шифртекст перед функцией invmixcolumns
        for i in range(4):
            before_inv_c_x.append([])
            for j in range(len(key_bundle[ROUND][i])):
                before_inv_c_x[i].append(bin(int(key[i][j], 2) ^ int(h_main[4 * i + j], 2))[2:])
                before_inv_c_x[i][j] = (8 - len(before_inv_c_x[i][j])) * '0' + before_inv_c_x[i][j]
        '-----------------------------------------------------------------'

        """//////////////////////////////////////////////////////////
            ////////////      INV MIX COLUMN     /////////////////
              ////////////////////////////////////////////////"""

        # constant: {0B}𝑥^3 + {0D}𝑥^2 + {09}𝑥 + {0E}

        '-------------------------C_X forming---------------------------'
        c_x = ['0b', '0d', '09', '0e']                  # полином c(x)^-1
        c_x_matrix = []                                 # матрица полинома c(x)^-1 в строках!

        for i in range(4):
            c_x_matrix.append([])                       # строка матрицы
            c_x_matrix[i] = c_x[3 - i:] + c_x[:3 - i]
        '------------------------C_X_MUL--------------------------'
        after_inv_c_x = []                              # шифртекст после invmixcolumns

        mul_arr = []                                    # массив в целых числах для удобных преобразований
        for i in range(len(before_inv_c_x)):
            mul_arr.append([])
            for j in before_inv_c_x[i]:
                mul_arr[i].append(int(j, 2))

        for col in range(4):
            after_inv_c_x.append([])
            for value in range(4):
                after_inv_c_x[col].append(identify(c_x_matrix[value], mul_arr[col]))
        '-----------------------------------------------------------------'

        """///////////////////////////////////////////////////////////
            ////////////////////  INV SHIFT ROWS //////////////////
              ///////////////////////////////////////////////// """

        # Массив after_inv_c_x представляет собой массив колонок сообщения State

        # Переводим массив State из колонок в строки

        enter_inv_sh_rows = []
        for i in range(4):
            enter_inv_sh_rows.append([])
            for j in range(4):
                enter_inv_sh_rows[i].append(after_inv_c_x[j][i])

        inv_sh_rows_tmp = []
        for i in range(len(enter_inv_sh_rows)):  # Делаем сдвиги байт по строкам
            inv_sh_rows_tmp.append(enter_inv_sh_rows[i][4 - i:])
            inv_sh_rows_tmp[i].extend(enter_inv_sh_rows[i][:4 - i])

        exit_inv_sh_rows = []
        for i in range(4):
            exit_inv_sh_rows.append([])
            for j in range(4):
                exit_inv_sh_rows[i].append(inv_sh_rows_tmp[j][i])
        '-----------------------------------------------------------------'

        """///////////////////////////////////////////////////////////
            ////////////////////  INV SUB BYTES //////////////////
                ////////////////////////////////////////////// """

        before_inv_subbytes = []

        for i in range(len(exit_inv_sh_rows)):
            for j in range(len(exit_inv_sh_rows)):
                tmp = hex(int(exit_inv_sh_rows[i][j], 2))[2:]
                tmp = "0" * (2 - len(tmp)) + tmp
                before_inv_subbytes.append(tmp)

        after_inv_sub_bytes = []

        after_inv_sub_bytes = sbox_searching(before_inv_subbytes, sbox_bundle[ROUND])  # здесь есть выбор sbox'а!
        '-----------------------------------------------------------------'

        # ОКОНЧАНИЕ РАУНДА:
        h_main = deepcopy(after_inv_sub_bytes)

    res = ''
    for value in h_main:
        tmp = int(value, 16)
        if value != '00':
            res += chr(tmp)
    print(f"Результат: {h_main} - {res}")

    with open("DECRYPTION_RESULT.txt", 'a', encoding='utf-8') as f:
        f.write(res)

sleep(1000)

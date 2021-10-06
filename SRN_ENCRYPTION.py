"""/////////////////////////////////////////////////////////////
        /////////////// ENTERING_ALGORITHM ///////////////
            ////////////////////////////////////////
                Алгоритм шифрования SRN_ENCRYPTION"""


from sys import exit
from os import listdir
from typing import List
import io
from os import linesep
from time import sleep
from timeit import default_timer
from copy import deepcopy
from os import system


def to_bit(file_value):  # Функция переводит символы в bin
    bits = ''
    for letter in file_value:
        bits += bin(ord(letter))[2:]
    bits = '0' * (128 - len(bits)) + bits
    return bits


def columns(file_value):
    position = 0
    for p in range(4):
        file_value.append(file_value[position:position + 4])
        position += 4
    file_value = file_value[16:]
    return file_value


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
            t_key_info.write(f"+ {flag} \n")
            tmp_shifted = shift(tmp_shifted)  # Повторная рекурсия

    return tmp_shifted


def s_box_searching(arr: object, sbox_val) -> object:
    keys_col_let = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']
    changed_arr = []

    for i in arr:
        count_1 = keys_col_let.index(i[0])
        count_2 = keys_col_let.index(i[1])
        for STRING in range(16):
            for COL in range(16):
                if count_1 == STRING:
                    if count_2 == COL:
                        changed_arr.append(sbox_val[count_1][count_2])  # Находим значение из S-Box
                else:
                    pass
    return changed_arr  # Целый массив без подмассивов


def getting_value(hex_table, element):
    for item, val in hex_table.items():
        if val[2] == element:
            return item


def length_check(number):
    if len(str(bin(number)[2:])) > 8:
        number = str(bin(number)[2:])
        number = number[len(number) - 8:]
        return int(number, 2)
    else:
        pass
    return number


def key_check(arr1, arr2):
    """ Для проверки на то,
    что действительные байты ключа не равны прошлым"""

    for column in range(4):
        for v in range(4):
            if arr1[column][v] == arr2[column][v]:
                return True
    else:
        return False


'Actions from Mix Column algorithm: '


def identify(matrix, arr):
    """Данная функция позволяет выбирать другие подфункции, чтобы
    перемножать элемент столбца массива сообщения с элементами многочлена c_x.
    В результате находится сумма всех получившихся значений из массива arr."""
    res = 0
    for value_i in range(len(arr)):
        if matrix[value_i] == "01":
            res = res ^ mul_01(arr[value_i])
        elif matrix[value_i] == "02":
            res = res ^ mul_02(arr[value_i])
        elif matrix[value_i] == "03":
            res = res ^ mul_03(arr[value_i])
    return bin(res)[2:]                             # выход в битах


def mul_01(arr_num):                                # Умножение на 1 (ничего не происходит)
    return arr_num


def mul_02(arr_num):                                # умножение на 10 (в двоичной)
    res = bin(arr_num)[2:]
    res = '0' * (8 - len(res)) + res
    res = res[1:] + '0'                             # сдвиг влево (нециклический!)
    if '0' * (8 - len(bin(arr_num)[2:])) + bin(arr_num)[2:][0] == '1':
        res = bin(int(res, 2) ^ int('11011', 2))    # искомая маска 0x1b
    return int(res, 2)


def mul_03(arr_num):                                # умножение на 11 (в двоичной)
    """При умножении на {03} мы можем представить тройку как 01 xor 10.
    После мы можем совершать действия над столбцом, раскрывая скобки. То есть,
    нам придется обратиться к двум предыдущим функциям, так как раскрытие скобок
    даст умножение."""

    arr_num = mul_02(arr_num) ^ mul_01(arr_num)
    return arr_num


def progressbar(iteration, total, prefix='', suffix='', decimals=1, length=100, fill='█', printEnd = "\r"):
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    # Print New Line on Complete
    if iteration == total:
        print(f'\r{prefix} |{bar}| {percent}% {suffix}', end=printEnd)
        print()
    else:
        print(f'\r{prefix} |{bar}| {percent}%', end=printEnd)

# --------------------------------------------------------------------
# HEX
key_h = {0: '0x0', 1: '0x1', 10: '0x2', 11: '0x3', 100: '0x4', 101: '0x5',
         110: '0x6', 111: '0x7', 1000: '0x8', 1001: '0x9', 1010: '0xa',
         1011: '0xb', 1100: '0xc', 1101: '0xd', 1110: '0xe', 1111: '0xf'}

# --------------------------------------------------------------------

t_key_info = open("statuses about t_key.txt", 'w')

'------------------------- FILE MAKING  --------------------------'
print('Files in an actual directory: ', '\n', listdir())  # Выводим список файлов для удобства работы
folder = str(input('Введите название папки с сообщением: '))
file_name_1 = str(input('Введите название файла с сообщением из этой папки (c форматом (.txt)): '))

try:
    file = open(f'./../{folder}/{file_name_1}', encoding='utf-8')  # Открываем файл
except FileNotFoundError:
    while True:
        print('Error occurred, press "f" to exit.')
        if str(input()) == 'f':
            exit(0)
        else:
            continue

    exit(0)
else:
    if file_name_1[len(file_name_1) - 4:] == '.txt':  # Проверка на формат
        pass
    else:
        while True:
            print('Error occurred, press "f" to exit.')
            if str(input()) == 'f':
                exit(0)
            else:
                continue
TEXT_line = str(file.read())

# сброс предыдущего результата:
with open("ENCRYPTION_RESULT.txt", 'w'): pass
# Здесь происходит распределение текста по блокам: каждый длиной 16 символов:
'''---------------------- FILE CUTTING -------------------------'''
TEXT_blocks = []

print('Содержимое файла: ')
print(TEXT_line)

counter = 0
for symbol in TEXT_line:
    if counter % 16 == 0:
        TEXT_blocks.append(symbol)
    else:
        TEXT_blocks[counter // 16] += symbol
    counter += 1
print(TEXT_blocks)
'''-------------------------------------------------------------'''

'-------------------------- KEY_MAKING ---------------------------'
folder = str(input('Введите название папки с ключом: '))
file_name_2 = str(input('Введите название файла с ключом из этой папки (c форматом (.txt)): '))

try:
    file = open(f'./../{folder}/{file_name_2}')  # Открываем файл
except FileNotFoundError:
    print('Error occurred.')
    exit(0)
else:
    if file_name_2[len(file_name_2) - 4:] == '.txt':  # Проверка на формат
        pass
    else:
        while True:
            print('Error occurred, press "f" to exit.')
            exit_v = str(input())
            if exit_v == 'f':
                exit(0)
            else:
                continue

initial_secret_key = file.read()
initial_secret_key = to_bit(initial_secret_key)

b_initial_secret_key = []  # Массив байт ключа
for i in range(len(initial_secret_key) // 8):  # Разделение ПЕРВОГО ключа по байтам
    b_initial_secret_key.append(initial_secret_key[:8])
    initial_secret_key = initial_secret_key[8:]

b_q_initial_secret_key = []  # Массив байт в квартетах
pos = 0
for i in range(len(b_initial_secret_key) // 4):  # разделение на квартеты начального ключа
    b_q_initial_secret_key.append(b_initial_secret_key[pos:pos + 4])
    pos += 4
print('Начальный ключ алгоритма: ', b_q_initial_secret_key)

reboot_key = deepcopy(b_q_initial_secret_key)  # Ключ в случае перегрузки
flag = 0  # дял корректной работы reboot'а

file.close()  # Закрываем файл
'-----------------------------------------------------------------'

'----------------------- S_BOX MAKING ----------------------------'
s_box = []  # Объявление поля s-box
folder = str(input('Введите название папки с таблицей Sbox: '))
try:
    with open(f'./../{folder}/GF.txt') as file_S:
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
print('СБОХ: ', s_box)
reboot_sbox = deepcopy(s_box)  # для каждого блока
'-----------------------------------------------------------------'

t1 = default_timer()  # засекаем время

system('cls')
main_progress_counter = 0
for main in TEXT_blocks:

    progressbar(main_progress_counter + 1, len(TEXT_blocks), prefix='Прогресс:', suffix='Процесс завершён', length=50)
    # print('BLOCK: ', main)
    '--------------------INLINE FILE TRANSFORMING--------------------'
    b_main_bits = ['00000000'] * 16  # Массив байт сообщения
    counter = 0
    for i in main:  # Разделение сообщения по байтам
        temporary = bin(ord(i))[2:]
        temporary = '0' * (8 - len(temporary)) + temporary
        b_main_bits[counter] = temporary
        counter += 1

    b_q_main_bits = []  # Массив байт в квартетах
    pos = 0
    for i in range(len(b_main_bits) // 4):  # разделение на квартеты начального сообщения
        b_q_main_bits.append(b_main_bits[pos:pos + 4])
        pos += 4

    file.close()  # Закрываем файл
    '-----------------------------------------------------------------'

    '----------------'
    tmp_sbox = []  # Необходим для изменения ключа
    '----------------'

    '----------------'
    s_box = deepcopy(reboot_sbox)  # объявление sbox'а
    '----------------'

    '----------------'
    b_q_initial_secret_key = deepcopy(reboot_key)  # объявление ключа
    '----------------'
    key_bundle = []

    for ROUND in range(9):
        flag = 0  # в случае ребута ключа

        '---------------------- FILE TRANSFORMING ------------------------'
        h_main = []
        tmp = ''
        for col in range(4):  # Переводим квартеты файла из bits в hex
            for elem in range(4):
                tmp = b_q_main_bits[col][elem]
                tmp = key_h[int(tmp[:4])][2:] + key_h[int(tmp[4:])][2:]  # key_h - словарь с hex
                h_main.append(tmp)

        if len(h_main) < 16:  # Добавляем нули до 16 байт (В начало)
            h_main = h_main[::-1]
            for i in range(16 - len(h_main)):
                h_main.append('00')
            h_main = h_main[::-1]
        else:
            pass

        # Переводим в колонны:
        h_main = columns(h_main)

        for i in range(4):  # Объединяем элементы списка (удобно совершать Shift_Row)
            h_main += h_main[i]
        h_main = h_main[4:]
        '-----------------------------------------------------------------'

        '---------------------- KEY TRANSFORMING ------------------------'
        t_secret_key = shift(b_q_initial_secret_key)  # Трансофрированный ключ
        count_check = 0  # переменная лимита трансформации
        while True:
            if key_check(t_secret_key, b_q_initial_secret_key):  # Если что-то равно из начального и временного ключей, то
                if flag > 2:  # вернулись к исходному ключу
                    '''///'''  # ни одного подобного случая
                    break
                elif count_check > 1000:  # лимит на трансмормацию
                    t_secret_key = deepcopy(reboot_key)  # Если не получается нормально преобразовать
                    break
                else:
                    count_check += 1
                    t_secret_key = shift(t_secret_key)
            else:
                break

        for i in range(4):  # XOR байт текущего ключа и начального
            for q in range(4):
                tmp = bin(int(t_secret_key[i][q], 2) ^ int(b_q_initial_secret_key[i][q], 2))[2:]
                t_secret_key[i][q] = '0' * (8 - len(tmp)) + tmp

        '-----------------------------------------------------------------'
        key_bundle.append(t_secret_key)

        """///////////////////////////////////////////////////////////
            ///////////////  BYTE SUB - ALGORITHM  ////////////////
              /////////////////////////////////////////////////"""

        ''' 
        Initial advanced version of S_Box:
        2b c4 4d a2 76 99 10 ff 56 b9 30 df 0b e4 6d 82
        db 34 bd 52 86 69 e0 0f a6 49 c0 2f fb 14 9d 72
        95 7a f3 1c c8 27 ae 41 e8 07 8e 61 b5 5a d3 3c
        65 8a 03 ec 38 d7 5e b1 18 f7 7e 91 45 aa 23 cc
        cb 24 ad 42 96 79 f0 1f b6 59 d0 3f eb 04 8d 62
        3b d4 5d b2 66 89 00 ef 46 a9 20 cf 1b f4 7d 92
        75 9a 13 fc 28 c7 4e a1 08 e7 6e 81 55 ba 33 dc
        85 6a e3 0c d8 37 be 51 f8 17 9e 71 a5 4a c3 2c
        6f 80 09 e6 32 dd 54 bb 12 fd 74 9b 4f a0 29 c6
        9f 70 f9 16 c2 2d a4 4b e2 0d 84 6b bf 50 d9 36
        d1 3e b7 58 8c 63 ea 05 ac 43 ca 25 f1 1e 97 78
        21 ce 47 a8 7c 93 1a f5 5c b3 3a d5 01 ee 67 88
        8f 60 e9 06 d2 3d b4 5b f2 1d 94 7b af 40 c9 26
        7f 90 19 f6 22 cd 44 ab 02 ed 64 8b 5f b0 39 d6
        31 de 57 b8 6c 83 0a e5 4c a3 2a c5 11 fe 77 98
        c1 2e a7 48 9c 73 fa 15 bc 53 da 35 e1 0e 87 68
        '''

        '///////////////////////OWN PART - S-BOX TRANSFORMING///////////////////////'
        '''tmp_sbox = deepcopy(s_box)  # Глубокое копирование sbox'а (НЕ НУЖНО)
    
        total_errors = 0
        high = 0
        for string in range(16):
            errors = 0
            tmp_col = 0             # Создаем для итерирования по tmp - ключу - ЭТО КОЛОНКА
            tmp_string = 0          # Аналогично предыдущему комментарию - ЭТО СТРОКА
            for col in range(16):
                s_box[string][col] = int(s_box[string][col], 16) ^ int(t_secret_key[tmp_col][tmp_string], 2)
                s_box[string][col] = hex(s_box[string][col])[2:]
                if len(s_box[string][col]) == 1:
                    s_box[string][col] = '0' + s_box[string][col]
                # ---------------------------------------------------- Organisation
                if (col + 1) % 4 == 0:  # Для перехода из одного подмассива в другой
                    tmp_col += 1
                tmp_string += 1
                tmp_string = tmp_string % 4
                # ------------------------------------------------------------------
        '///////////////////////////////////////////////////////////////////////////'
        print('Временный sbox: ', tmp_sbox)
        print('Новый Sbox: ', s_box)
        
        Выше представлен фрагмент кода с перемешиванием sbox'а при помощи XORа байт ключа и таблицы соответственно.
        Я заметил такую вещь - такое сложение может дать в таблице одинаковые элементы в некоторых клетках.
        Тогда таблица является неправильной, ибо в инвертированной таблице в некоторых позициях будут нули!
        Я решил считать количество единиц в ключе, находить остаток от деленяи на 2, а затем делать сдвиг в таблице
        вправо или влево соответственно. Таким образом, значения не изменяются
        '''
        # ^ ВАЖНО
        # |
        # |
        # |

        sbox_shift_val = 0
        for col in t_secret_key:
            for string in col:
                for symbol in string:
                    if symbol == '1': sbox_shift_val += 1
        sbox_shift_val = sbox_shift_val % 2

        if sbox_shift_val == 1:                                   # сдвиг вправо
            for row in range(len(s_box)):
                s_box[row] = s_box[row][15:] + s_box[row][:15]
        else:                                                     # сдвиг влево
            for row in range(len(s_box)):
                s_box[row] = s_box[row][1:] + s_box[row][:1]

        '>>>>>>>>>>>'
        changed_rows: List[str] = s_box_searching(h_main, s_box)  # Sub_Bytes ~~~~~~~~~~~~~~~~~~~
        '>>>>>>>>>>>'

        # Было решено убрать этот блок кода вследствие сложности реализации расшифрования
        ''''>>>>>>>>>>>>>>>>>> ПОВТОРНОЕ ИЗМЕНЕНИЕ КЛЮЧА:'
        # Используется s_box предыдущего раунда
        # Происходит обычная функция SubBytes
        if ROUND == 0:
            pass
        else:
            tmp_key = []
            for i in range(len(t_secret_key)):
                col_of_key = deepcopy(t_secret_key[i])
                for element in range(len(col_of_key)):
                    first = hex(int(col_of_key[element][:4], 2))[2:]
                    second = hex(int(col_of_key[element][4:], 2))[2:]
                    col_of_key[element] = first + second
                tmp_key.extend(col_of_key)
            tmp_key = s_box_searching(tmp_key, tmp_sbox)
    
            t_secret_key = []
            pos = 0
            for i in range(len(tmp_key) // 4):
                t_secret_key.append(tmp_key[pos:pos + 4])
                pos += 4
    
            for col in range(4):
                for value in range(4):
                    first = bin(int(t_secret_key[col][value][0], 16))[2:]
                    second = bin(int(t_secret_key[col][value][1], 16))[2:]
                    t_secret_key[col][value] = first + second
        print('ИЗМЕНЕНИЕ КЛЮЧА TMPKEYFORMING: ', t_secret_key)'''

        """///////////////////////////////////////////////////////////
            //////////////  SHIFT ROW - ALGORITHM  ////////////////
              ///////////////////////////////////////////////// """

        enter_sh_rows = []
        for i in range(len(changed_rows) // 4):  # Объявляем обработанный  массив в квартетах (4 х 4) в строках
            enter_sh_rows.append(changed_rows[i::4])

        sh_rows_tmp = []
        for i in range(len(enter_sh_rows)):      # Делаем сдвиги байт по строкам
            sh_rows_tmp.append(enter_sh_rows[i][i:])
            sh_rows_tmp[i].extend(enter_sh_rows[i][:i])

        tmp = []                                 # Целый массив без подмассивов из sh_rows_tmp
        for i in sh_rows_tmp:
            tmp += i
        sh_rows_tmp = tmp

        sh_rows = []
        for i in range(len(sh_rows_tmp) // 4):   # Переводим в колонны снова
            sh_rows.append(sh_rows_tmp[i::4])

        """///////////////////////////////////////////////////////////
            //////////////  MIXCOLUMNS - ALGORITHM  ///////////////
              /////////////////////////////////////////////////"""

        # sh_rows - state, сдвинутый по байтам
        for col in sh_rows:             # Преобразование массива с передвинутыми рядами в битный вид
            for value in range(len(col)):
                first_part = bin(int(col[value][0], 16))[2:]
                second_part = bin(int(col[value][1], 16))[2:]
                col[value] = '0' * (4 - len(first_part)) + first_part + '0' * (4 - len(second_part)) + second_part

        '-------------------------C_X forming---------------------------'
        c_x = ['03', '01', '01', '02']  # полином c(x)
        c_x_matrix = []                 # матрица полинома c(x) в строках!

        for i in range(4):
            c_x_matrix.append([])       # строка
            c_x_matrix[i] = c_x[3 - i:] + c_x[:3 - i]
        '------------------------C_X_MUL--------------------------'
        # Здесь мы производим перемножение всех элементов c_x_matrix с sh_rows
        # по матричному принципу!
        after_c_x = []

        mul_arr = []                    # массив в целых числах для удобных преобразований
        for i in range(len(sh_rows)):
            mul_arr.append([])
            for j in sh_rows[i]:
                mul_arr[i].append(int(j, 2))

        for col in range(4):
            after_c_x.append([])
            for value in range(4):
                after_c_x[col].append(identify(c_x_matrix[value], mul_arr[col]))  # Xor ряда матрицы полинома с sh_rows
        '-----------------------------------------------------------------'

        '------------------ XOR FILE WITH KEY IN BITS --------------------'
        xor_main_bits = []
        for col in range(4):
            xor_main_bits.append([])
            for elem in range(4):
                tmp = bin(int(after_c_x[col][elem], 2) ^ int(t_secret_key[col][elem], 2))[2:]
                tmp = '0' * (8 - len(tmp)) + tmp
                xor_main_bits[col].append(tmp)
        '-----------------------------------------------------------------'

        '///////////////////MAIN_BITS_LOOP_END///////////////////////'
        b_q_main_bits = deepcopy(xor_main_bits)
        b_q_initial_secret_key = deepcopy(t_secret_key)  # Передаем значение ключа в начало цикла

    """///////////////////////////////////////////////////////////
        /////////////////  EXITING ALGORITHM  //////////////////
          /////////////////////////////////////////////////"""

    result = ''

    for i in range(4):
        for j in range(4):
            tmp = hex(int(xor_main_bits[i][j], 2))[2:]
            result = result + '0' * (2 - len(tmp)) + tmp
            result += ' '

    # print('Результат шифрования: ', result)
    with io.open('ENCRYPTION_RESULT.txt', 'a', encoding='utf-8') as file:  # Запись файла
        file.write(result)
        file.write(linesep)
    file.close()

    main_progress_counter += 1


all_time = str(default_timer() - t1)
print(f'Время выполнения - {all_time}')
with io.open('time_list', 'a', encoding='utf-8') as file:
    file.write(all_time)
    file.write(linesep)
sleep(1000)

with open("ENCRYPTION_RESULT.txt", 'a', encoding='utf-8') as f:
    f.write('SRN-ENC')
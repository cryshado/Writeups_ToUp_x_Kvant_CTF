## Writeups ToUp x Kvant CTF

### fsociety (ppc | crypto | forensic)

Мы видим файл `fsociety.dat.crp` - это зашифрованный файл алгоритмом `AES256`. 

Гуглим название таска.

Понимаем, что ключом к расшифровке файла является адресс убежища `fsociety` из сериала `Mr.Robot` - из google maps - `1251-1201 Bowery St, Brooklyn, NY 11224`
(https://goo.gl/maps/kPMUQ1msAw3NUuFN6)

Напишем `decrypt.py`:

```python
# -*- coding: utf-8 -*-
import os
import pyAesCrypt
import sys

def decrypt(file):
	password="1251-1201 Bowery St, Brooklyn, NY 11224"
	buffer_size = 512*1024
	pyAesCrypt.decryptFile(file, os.path.splitext(file)[0], password, buffer_size)

decrypt('fsociety.dat.crp')
```

После расшифровки файла с помощью `decrypt.py` получаем файл `fsociety.dat`

Его содержимое:
```
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XX                                                                          XX
XX   MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM   XX
XX   MMMMMMMMMMMMMMMMMMMMMssssssssssssssssssssssssssMMMMMMMMMMMMMMMMMMMMM   XX
XX   MMMMMMMMMMMMMMMMss'''                          '''ssMMMMMMMMMMMMMMMM   XX
XX   MMMMMMMMMMMMyy''                                    ''yyMMMMMMMMMMMM   XX
XX   MMMMMMMMyy''                                            ''yyMMMMMMMM   XX
XX   MMMMMy''                                                    ''yMMMMM   XX
XX   MMMy'                                                          'yMMM   XX
XX   Mh'                                                              'hM   XX
XX   -                                                                  -   XX
XX                                                                          XX
XX   ::                                                                ::   XX
XX   MMhh.        ..hhhhhh..                      ..hhhhhh..        .hhMM   XX
XX   MMMMMh   ..hhMMMMMMMMMMhh.                .hhMMMMMMMMMMhh..   hMMMMM   XX
XX   ---MMM .hMMMMdd:::dMMMMMMMhh..        ..hhMMMMMMMd:::ddMMMMh. MMM---   XX
XX   MMMMMM MMmm''      'mmMMMMMMMMyy.  .yyMMMMMMMMmm'      ''mmMM MMMMMM   XX
XX   ---mMM ''             'mmMMMMMMMM  MMMMMMMMmm'             '' MMm---   XX
XX   yyyym'    .              'mMMMMm'  'mMMMMm'              .    'myyyy   XX
XX   mm''    .y'     ..yyyyy..  ''''      ''''  ..yyyyy..     'y.    ''mm   XX
XX           MN    .sMMMMMMMMMss.   .    .   .ssMMMMMMMMMs.    NM           XX
XX           N`    MMMMMMMMMMMMMN   M    M   NMMMMMMMMMMMMM    `N           XX
XX            +  .sMNNNNNMMMMMN+   `N    N`   +NMMMMMNNNNNMs.  +            XX
XX              o+++     ++++Mo    M      M    oM++++     +++o              XX
XX                                oo      oo                                XX
XX           oM                 oo          oo                 Mo           XX
XX         oMMo                M              M                oMMo         XX
XX       +MMMM                 s              s                 MMMM+       XX
XX      +MMMMM+            +++NNNN+        +NNNN+++            +MMMMM+      XX
XX     +MMMMMMM+       ++NNMMMMMMMMN+    +NMMMMMMMMNN++       +MMMMMMM+     XX
XX     MMMMMMMMMNN+++NNMMMMMMMMMMMMMMNNNNMMMMMMMMMMMMMMNN+++NNMMMMMMMMM     XX
XX     yMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMy     XX
XX   m  yMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMy  m   XX
XX   MMm yMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMy mMM   XX
XX   MMMm .yyMMMMMMMMMMMMMMMM     MMMMMMMMMM     MMMMMMMMMMMMMMMMyy. mMMM   XX
XX   MMMMd   ''''hhhhh       odddo          obbbo        hhhh''''   dMMMM   XX
XX   MMMMMd             'hMMMMMMMMMMddddddMMMMMMMMMMh'             dMMMMM   XX
XX   MMMMMMd              '<flag_ctf:(?-You1or0-?)>'              dMMMMMM   XX
XX   MMMMMMM-               ''ddMMMMMMMMMMMMMMdd''               -MMMMMMM   XX
XX   MMMMMMMM                   '::dddddddd::'                   MMMMMMMM   XX
XX   MMMMMMMM-                                                  -MMMMMMMM   XX
XX   MMMMMMMMM                                                  MMMMMMMMM   XX
XX   MMMMMMMMMy                                                yMMMMMMMMM   XX
XX   MMMMMMMMMMy.                                            .yMMMMMMMMMM   XX
XX   MMMMMMMMMMMMy.                                        .yMMMMMMMMMMMM   XX
XX   MMMMMMMMMMMMMMy.                                    .yMMMMMMMMMMMMMM   XX
XX   MMMMMMMMMMMMMMMMs.                                .sMMMMMMMMMMMMMMMM   XX
XX   MMMMMMMMMMMMMMMMMMss.           ....           .ssMMMMMMMMMMMMMMMMMM   XX
XX   MMMMMMMMMMMMMMMMMMMMNo         oNNNNo         oNMMMMMMMMMMMMMMMMMMMM   XX
XX                                                                          XX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

    .o88o.                               o8o                .
    888 `"                               `"'              .o8
   o888oo   .oooo.o  .ooooo.   .ooooo.  oooo   .ooooo.  .o888oo oooo    ooo
    888    d88(  "8 d88' `88b d88' `"Y8 `888  d88' `88b   888    `88.  .8'
    888    `"Y88b.  888   888 888        888  888ooo888   888     `88..8'
    888    o.  )88b 888   888 888   .o8  888  888    .o   888 .    `888'
   o888o   8""888P' `Y8bod8P' `Y8bod8P' o888o `Y8bod8P'   "888"      d8'
                                                                .o...P'
                                                                `Yd8P'
```

Видим флаг - `<flag_ctf:(?-You1or0-?)>`



### somecode (ppc | crypto)

(описание)
```
When Russian Hacker Vasiliy drinking Vodka and playing the balalaika he decided to learn programming, but he can't choose what language he wont to learn. He started watching 5 lessons about different programming languages. After he wrote first program — "Hello World", he started writing encryption code to encrypt servers in all countries of the world. He developed the code, but unfortunately couldn't run it.
Let's help Our Sweet CoolHacker!
```

Из скачанного архива мы получаем 2 файла: первый — (coming_out) зашифрованный флаг, второй — (some_code) алгоритм шифрации на `ПСЕВДОКОДЕ`. Это слово должно сразу у вас вызвать подёргивание левого глаза! 

Ну да ладно, перейдём к анализу данного алгоритма. Его можно даже не переписывать, чтобы сэкономить время, а анализировать просто так.

Первым делом мы пожем понять, что код испорчен, как нам и обещали в описании. После долгих танцев с бубнами вокруг редактора, понимаем, что нам надо, что не надо из тех строчек, что закоментированы. Я не буду сейчас описывать полный процесс этого действа, так как это - дело техники, надо просто делать то, что написано. 

Далее идёт уже анализ алгоритма. Мы видим класс dyn_numsys. Если включить фантазию, мы, очевидно, понимаем, что под этим автор понимал dynamical number systems — левый глаз начинает дёргаться ещё сильнее... Смотрим дальше по классу: объявление переменных, default constructor, потом его перегрузка, с нестандартными значениями - это всё не интересно, далее функция determine_footing, - определение системы счисления - наши опасения подтверждаются... Оператор плюс - а оформлен как функция - костыль! А, нет, далее он используется в перегрузке оператора + (попахивает С++:)) Ну зашли мы в неё, смотрим... Понимаем, что применяться она может ещё и для чисел в разных системах - ~~МОЗГ КИПИТ~~ - идём дальше... Видим, что берётся максимальное основание системы - это самое важное, остальное - просто код, который должен работать. 

функция get_dec - получить число в десятеричной системе - видимо оно тоже надо. 

Далее техническая часть - перегрузка логических и арифметических операторов - 100% C++ 

function main() - оооо, наконец-то вот отсюда и надо было начинать, ну да ладно. Ай, больно, оказывается мы берём среднее арифметическое двух очередных символов флага (а символы то так-то стандартные, из ascii, да вот толко в разных системах счисления. Сложены они в максимальной, а поделены на 2 - в десятичной. Далее распиханы на 2 символа. Вот и весь алгоритм. Просто? Кажется да, но вот толко теперь надо это всё расшифровать... Левый глаз чуть ли не выпадает. 

Ладно, пошли декодить! 

Идея: Взять закодированную строку и попарно складывать коды элементов - соответственно в десятеричной системе. Что это - это как раз сумма кодов первых 2 символов флага. Только вот, в какой она должна быть системе - вопрос. Для этого нам нужен собственно первый - тобишь нулквой символ флага. Не вопрос - смотрим на форматы флагов :
```
<flag_rznctf:(флаг)>
<flag_ctf:(флаг)>
```
ага - первый символ - "<" его код нам и нужен. Для этого кода мы и определяем минимальное основание. Но мыже могли складывать и не в нём - тут только перебор. Начиная от минимального основания вычитаем из полученной суммы ascii значение нулевого символа. Запишем результат в переменную temp_res, так вот если её минимальное основание равно минимальному основанию "<" то оно нам подходит, мы говорим, что temp_res является очередным символом флага. Далее - дело техники, оборачиваем это всё дело в цикл и просто записываем очередное полученное значение в переменную. Его мы будем использовать на следующей итерации вместо "<". Единственное, надо сделать оговорку, что если мы не нашли минимальное подходящее основание в цикле, за него мы принимаем то, что является минимальным основанием для суммы очередных двух соседних пикселей. Вот в общем-то и всё. Вот пример реализации на C++:

```C++
#include <fstream>
#include <iostream>
#include <string>
#include <cmath>

int get_min_footing(int num)
{
    int res = 0;
    for (int i = num; i != 0; i /= 10)
            if (i > 0 && i % 10 + 1 > res)
                res = i % 10 + 1;

    return res;
}

int MinuseOperator(int a, int b, int footing)
{
    int len = std::to_string(a).size();
    int *res = new int[len];

    for (int i = 0; i < len; i++)
    {
        res[i] = a % 10;
        a /= 10;
    }

	for (int i = 0, j = b; i < len && j != 0; i++, j /= 10)
	{
		if (res[i] < 0)
		{
			res[i] = footing - 1;
			res[i + 1]--;
		}

		if (res[i] >= j % 10)
            res[i] -= j % 10;
		else
		{
			res[i] = res[i] + footing - j % 10;
			res[i + 1]--;
		}
	}

    for (int i = len - 1; i >= 0; --i)
        if (res[i] != 0)
            break;
        else
            res[i] = -1;

    int result = 0;
    for (int i = len - 1; i >= 0; --i)
    {
        if (res[i] != -1)
        {
            result *= 10;
            result += res[i];
        }
    }

	return result;
}

int get(int num, int footing)
{
    std::string asd = "";
    int res = 0;

    while (num != 0)
    {
        asd += num % footing + 48;
        num /= footing;
    }

    for (int i = asd.size() - 1; i >= 0; --i)
    {
        res *= 10;
        res += asd[i] - 48;
    }
    
    return res;
}

int main()
{
    std::ifstream fin; fin.open("coming_out.txt");
    std::string init; 
    std::string res = "<";

    char last = '<';

    std::ofstream fout; fout.open("some_flag.txt")

    std::string tmp;
    for (;std::getline(fin, tmp);)
        init += tmp + "\n";

    for (int i = 1; i < init.size(); i += 2)
    {
        int temp = (int)init[i] + init[i - 1];
        int min_footing = get_min_footing(last);
        int temp_res;
        bool was = false;

        for (int j = min_footing; j <= 10; ++j)
        {
            temp_res = MinuseOperator(get(temp, j), last, j);

            if (get_min_footing(temp_res) == j && temp_res < 128 && temp_res > 32)
            {
                res += temp_res;
                was = true;
                break;
            }
        }

        if (was)
            last = temp_res;
        else
        {
            last = MinuseOperator(get(temp, min_footing), last, min_footing);
            res += last;
        }
    }

    fout << res;
    fin.close();
    fout.close();

    return 0;
}
```
В итоге получаем флаг : `<flag_ctf:(dkFW8efklf232kulbAADWd1sl1MkoaSA)>`


### ManyLines (ppc) 

Если мы подключимся к серверу то получим:
```
Hey try this :) # MTI1MOODlOOCteOBruatuw==
RzFKTDhKelBpSGFYVzczckttWWt5TWhQZ2ZyRDBtVFhCQTVGdHFVcDdpcHhpZElrSFAxMVdTWmdzb2RrcHRmaUVoa0ZBVjFwTWZHQ1pT
NVp6RnRySGJmT0dDVzBUS1BEQks3NnRJb29DTVA=
```

`Hey try this :) # MTI1MOODlOOCteOBruatuw==` 

Всегда будет одинаковым, а вот строки дальше могут отличаться, `MTI1MOODlOOCteOBruatuw==` 
это подсказка к тому, что в таске будут числа Фибоначчи. Если мы расшифруем строку в base64
то получим `1250ピサの死`, видим, что это японский. Переведём например на английский и получим 
`Death of 1250 Pisa`, гуглим, нагугливаем что-то про дату и место смерти Фибоначчи. 

Далее видим строку. Например:
```
RzFKTDhKelBpSGFYVzczckttWWt5TWhQZ2ZyRDBtVFhCQTVGdHFVcDdpcHhpZElrSFAxMVdTWmdzb2RrcHRmaUVoa0ZBVjFwTWZHQ1pT
NVp6RnRySGJmT0dDVzBUS1BEQks3NnRJb29DTVA=
```
И возможность что-то отправить в ответ. Расшифруем строку в base64 и шифром Цезаря(до шифра Цезаря нужно было догодаться, но организаторы давали hint) первый раз со сдвигом 0 и в последующих итерациях следуя последовательности числе фибаначи 
менять сдвиг. Если сервер принял ответ то мы получим новую строку. Нужно написать
код который будет быстро отправлять такие строки, так как у сервера тайм-аут 
в 5 секунд. 

Вот код, который я написал:
```python3
# -*- coding: utf-8 -*-
from pwn import *
import base64
from caesarcipher import CaesarCipher

host = '212.26.237.212'
port = 4444

def fibonacci():
	a, b = 0, 1
	while True:
		yield a
		a, b = b, a + b

nc = remote(host, port)

hint = nc.recvline()
print(hint)

for n in fibonacci():
	read = nc.recvline().decode().replace('Hey try this :) # ', '')

	print(f'Received: {read}')

	try:
		base64_decode = base64.b64decode(read.encode("UTF-8"))
	except base64.binascii.Error:
		break

	to_send = CaesarCipher(base64_decode.decode('utf-8'), offset=n).decoded

	print(f'Sent: {to_send}')
	print('----------')

	nc.sendline(to_send.encode())
```

Сервер может зопросить рандомное n колв итераций в разумных рамках(в среднем около 1000). После выполнения
если всё было успешно мы получим:
`Well done! Your flag is <flag_ctf:(ef23UQTE42daiojjdQD#D&FT@)>`


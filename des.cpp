#include <vector>
#include <iostream>
#include <fstream>
#include <string>

using namespace std;

#define WRONG_KEY_SIZE 100	// код исключения при неверном размере ключа
#define WRONG_DATA_SIZE 101	// код исключения при неверном размере данных для шифрования

class DESCoder
{
public:
	// кодирование DES определяется ключом
	// поэтому создан только один конструктор на основе 8-байтного ключа
	// здесь не будем пользоваться сокращением vecUnsChar,
	// чтобы вне этого класса не пришлось угадывать, что это значит
	DESCoder(vector<unsigned char> key);

	// публичный метод - шифрование 8 байт, 
	// на выходе - зашифрованные 8 байт
	vector<unsigned char> encode(vector<unsigned char> data);

	// для дешифрования всё в точности наоборот
	vector<unsigned char> decode(vector<unsigned char> data);


	// весь алгоритм (функции и переменные) скрыт в области private
private:
	// так как шифрование и дешифрование DES отличаются только порядком передачи
	// ключей в 16 шагах алгоритма, обобщим эти 2 функции в одну
	vector<unsigned char> _process(vector<unsigned char> data, bool encode);

	vector<unsigned char> _dataBits;			// данные, которые необходимо закодировать (массив бит)
	vector<vector<unsigned char> > _keys;		// ключи, которые необходимо использовать для шифрования

	vector<unsigned char> _left;		// левая половина данных
	vector<unsigned char> _right;		// правая половина данных

	// начальная и конечная перестановка бит
	void _IP();
	void _inverseIP();

	// генерация ключей для каждого шага шифрования
	// на основе ключа, получаемого при создании шифратора
	void _generateKeys(vector<unsigned char> key64);
	vector<unsigned char> _shiftKeyLeft(vector<unsigned char> key56, int numShifts); // вспомогательная функция для генерации ключей

	// один шаг алгоритма DES
	// всего выполняется 16 шагов
	void _makeDesStep(vector<unsigned char> iKey);

	// шаг алгоритма DES состоит из следущих шагов:
	vector<unsigned char> _expansion(); // расширяет _right до 48 бит

	// после этого расширенный right48 ксорится с очередным ключом
	// затем 48-битный блок проходит S-блоки - substitution
	// на выходе которых - 32-битный блок
	vector<unsigned char> _substitution(vector<unsigned char> right48);

	// полученный после S-блоков 32-битный блок подвергается
	// очередной перестановке - P-блоку
	vector<unsigned char> _permutation(vector<unsigned char> right32);

	// после этого полученный блок ксорится с левой частью
	// и они меняются местами
	// на этом один из 16 шагов заканчивается


	// далее идут вспомогательные методы

	// вспомогательная функция представления байта как массив 0 и 1
	vector<unsigned char> _byteToBits(unsigned char byte);

	// вспомогательная функция для представления массива байт как массив 0 и 1
	vector<unsigned char> _bytesArrayToBits(vector<unsigned char> bytes);

	// вспомогательная функция представления массива бит как единого байта
	unsigned char _bitsToByte(vector<unsigned char> bits);

	// вспомогательная функция для представления массива бит как массив байт
	vector<unsigned char> _bitesArrayToBytes(vector<unsigned char> bites);
};

// конструктор шифратора на основе ключа,
// потому как шифратор определяется только ключом,
// все остальные составляющие алгоритма стандартизированны
DESCoder::DESCoder(vector<unsigned char> key)
{
	// размер ключа - 64 бита (8 байт)
	// и никакого другого
	if (key.size() != 8)
	{
		//throw WRONG_KEY_SIZE;
		cout << "Error: Wrong key size." << endl;
		exit(0);
	}

	vector<unsigned char> key64 = _bytesArrayToBits(key); // переводим ключ в массив бит

	// сгенерируем ключи для каждого шага
	_generateKeys(key64);
}

// функции шифрования и дешифрования отличаются только порядком 
// передачи ключей в 16 шагах, поэтому они обе будут вызывать _process,
// но только с разными флагами
vector<unsigned char> DESCoder::encode(vector<unsigned char> data)
{
	return _process(data, true);
}

vector<unsigned char> DESCoder::decode(vector<unsigned char> data)
{
	return _process(data, false);
}

// собсвенно, основная функция - функция шифрования
// (она же - дешифрования, отличаются только порядком передачи ключей)
vector<unsigned char> DESCoder::_process(vector<unsigned char> data, bool encode)
{
	// размер данных для шифрования - 64 бита (8 байт)
	// и никакого другого
	if (data.size() != 8)
	{
		//throw WRONG_DATA_SIZE;
		cout << "Error: Wrong data size." << endl;
		exit(0);
	}

	// представляем входные данные в виде массива бит
	_dataBits = _bytesArrayToBits(data);

	// проводим первоначальную перестановку
	// хотя в общем-то, она бессмыслена, но её требует стандарт
	_IP();

	// разделяем входные биты на левую и правую половины
	_left.clear();
	_left.insert(_left.end(), _dataBits.begin(), _dataBits.begin() + 32);
	_right.clear();
	_right.insert(_right.end(), _dataBits.begin() + 32, _dataBits.end());

	// далее выполняются 16 основных шагов алгоритма,
	// в которых преобразуются правая и левая части
	for (int i = 0; i < 16; i++)
	{
		// шифрование и дешифрование отличаются только порядком передачи ключей
		if (encode)
			_makeDesStep(_keys[i]);
		else
			_makeDesStep(_keys[15 - i]);
	}

	// на последнем шаге половинки поменялись местами, 
	// хотя не должны были этого делать. Исправим ситуацию
	vector<unsigned char> tmp = _right;
	_right = _left;
	_left = tmp;

	// после этого собираем вместе правую и левую половины
	_dataBits.clear();
	_dataBits.insert(_dataBits.end(), _left.begin(), _left.end());
	_dataBits.insert(_dataBits.end(), _right.begin(), _right.end());

	// и проводим окончательную перестановку, обратную первой,
	// которая тоже бессмысленна, но её требует стандарт
	_inverseIP();

	// теперь массив бит превращаем обратно в массив байт
	vector<unsigned char> result = _bitesArrayToBytes(_dataBits);

	// на этом всё, возвращаем результат
	return result;
}

// начальная перестановка бит
//Initail Permutation (IP)
void DESCoder::_IP()
{
	// массив новых позиций бит
	unsigned char ip[] = {
		58, 50, 42, 34, 26, 18, 10, 2,
		60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6,
		64, 56, 48, 40, 32, 24, 16, 8,
		57, 49, 41, 33, 25, 17, 9, 1,
		59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5,
		63, 55, 47, 39, 31, 23, 15, 7
	};

	vector<unsigned char> newDataBits(64); // куда будет записана перестановка
	for (int i = 0; i < 64; i++)
		newDataBits[i] = _dataBits[ip[i] - 1]; // собсвтвенно, сама перестановка

	this->_dataBits = newDataBits;
	return;
}

// конечная перестановка бит
void DESCoder::_inverseIP()
{
	unsigned char fp[] = {
		40, 8, 48, 16, 56, 24, 64, 32,
		39, 7, 47, 15, 55, 23, 63, 31,
		38, 6, 46, 14, 54, 22, 62, 30,
		37, 5, 45, 13, 53, 21, 61, 29,
		36, 4, 44, 12, 52, 20, 60, 28,
		35, 3, 43, 11, 51, 19, 59, 27,
		34, 2, 42, 10, 50, 18, 58, 26,
		33, 1, 41, 9, 49, 17, 57, 25
	};

	vector<unsigned char> newDataBits(64); // куда будет записана перестановка
	for (int i = 0; i < 64; i++)
		newDataBits[i] = _dataBits[fp[i] - 1]; // собсвтвенно, сама перестановка

	this->_dataBits = newDataBits;

	return;
}

// генерация 48-битных ключей для каждого из 16 шагов алгоритма
// довольно запутанная вещь
// на входе - 64-битный ключ DES
// на выходе - 16 48-битных ключей для каждого шага алгоритма
// (будут записаны в this->_keys)
void DESCoder::_generateKeys(vector<unsigned char> key64)
{
	this->_keys.clear();

	// сначала 64-битный ключ DES уменьшается до 56 бит
	// отбрасыванием каждого 8-го бита
	// при этом меняется порядок бит

	// массив - правило выбора и перемешивания 56 бит из 64
	unsigned char pc1[] = {
		57, 49, 41, 33, 25, 17, 9, 1,
		58, 50, 42, 34, 26, 18, 10, 2,
		59, 51, 43, 35, 27, 19, 11, 3,
		60, 52, 44, 36, 63, 55, 47, 39,
		31, 23, 15, 7, 62, 54, 46, 38,
		30, 22, 14, 6, 61, 53, 45, 37,
		29, 21, 13, 5, 28, 20, 12, 4
	};

	vector<unsigned char> key56(56); // куда будет записан 56-битный ключ
	for (int i = 0; i < 56; i++)
		key56[i] = key64[pc1[i] - 1];

	// затем генерируется 16 48-битных ключей
	// Для этого в каждом шаге 56-битный ключ делится на 2 половины, и каждая из половинок
	// циклически сдвигается влево на 1 или 2 позиции в зависимости от номера шага
	// (циклический сдвиг половионок осуществляет функция shiftKeyLeft)
	// и на основе этого 56-битного сдвинутого ключа
	// генерируется очередной 48-битный ключ
	// (перестановка со сжатием)

	unsigned char leftShifts[] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 }; // правила сдвига

	// правило генерации 48-битного ключа на основе 56-битного
	unsigned char pc2[] = {
		14, 17, 11, 24, 1, 5, 3, 28,
		15, 6, 21, 10, 23, 19, 12, 4,
		26, 8, 16, 7, 27, 20, 13, 2,
		41, 52, 31, 37, 47, 55, 30, 40,
		51, 45, 33, 48, 44, 49, 39, 56,
		34, 53, 46, 42, 50, 36, 29, 32
	};

	for (int j = 0; j < 16; j++)
	{
		// сдвигаем половинки ключа
		key56 = _shiftKeyLeft(key56, leftShifts[j]);

		vector<unsigned char> iKey(48); // очередной ключ
		for (int i = 0; i < 48; i++)
		{
			iKey[i] = key56[pc2[i] - 1]; // генерация 48-битного ключа на основе 56-битного
		}

		this->_keys.push_back(iKey);
	}

}

// вспомогательная функция для генерации ключей
// сдвигает половины 56-битного ключа на 1 или 2 позиции влево
vector<unsigned char> DESCoder::_shiftKeyLeft(vector<unsigned char> key56, int numShifts)
{
	while (numShifts > 0)
	{
		unsigned char t1 = key56[0];
		unsigned char t2 = key56[28];

		for (int i = 0; i < 55; i++)
		{
			if (i == 27)
				continue;
			else
				key56[i] = key56[i + 1];
		}
		key56[27] = t1;
		key56[55] = t2;
		numShifts--;
	}

	return key56;
}


// один шаг алгоритма DES
// суть:
// left[i] = right[i - 1]
// right[i] = left[i - 1] ^ F( right[i - 1], key[i] )
// весь прикол в:
//		перестановке right с расширением
//		подстановках в 8 S-блоках
//		перестановках в P-блоке
//		и не забыть поксорить нужные блоки
// это при том, что на вход подается уже сгенерированный очередной ключ
void DESCoder::_makeDesStep(vector<unsigned char> iKey)
{
	// перестановка right с расширением
	// часто называемая expansion
	// расширяем 32-битный _right до 48 бит
	vector<unsigned char> right48 = _expansion();

	// теперь необходимо поксорить полученный 48-битный блок 
	// с 48-битным ключом
	for (int i = 0; i < 48; i++)
		right48[i] = right48[i] ^ iKey[i];

	// теперь самая интересная часть: S-блоки
	// Подстановка с помощью S-блоков является ключевым этапом DES
	// Другие действия алгоритма линейны и легко поддаются анализу
	// S-блоки нелинейны, и именно они в большей степень определяют безопасность алгоритма
	// На вход S-блоков поступает 48-битный right48 (уже поксореный с ключом), 
	// на выходе - 32-битный блок right32
	vector<unsigned char> right32 = _substitution(right48);

	// после этого полученный блок подвергается очередной перестановке
	right32 = _permutation(right32);

	// после этого он ксорится с левым блоком
	for (int i = 0; i < 32; i++)
		right32[i] = right32[i] ^ _left[i];

	// при этом новый левый блок - старый правый
	_left = _right;

	// а правый - результат работы этих страшных функций
	_right = right32;

	// на этом шаг алгоритма DES заканчивается
}

// расширение right до 48 бит
vector<unsigned char> DESCoder::_expansion()
{
	// правило расширение 32-битного _right до 48 бит
	unsigned char E[] = {
		32, 1, 2, 3, 4, 5, 4, 5,
		6, 7, 8, 9, 8, 9, 10, 11,
		12, 13, 12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21, 20, 21,
		22, 23, 24, 25, 24, 25, 26, 27,
		28, 29, 28, 29, 30, 31, 32, 1
	};

	vector<unsigned char> expanded(48);
	for (int i = 0; i < 48; i++)
		expanded[i] = this->_right[E[i] - 1];

	return expanded;
}

// подстановки с помощью 8 S-блоков
// S-блоки - таблицы 4x16, каждый элемент которой -
// 4-битное число
// S-блок ставит в соответствие каждым 6 битам 4 бита из таблицы
vector<unsigned char> DESCoder::_substitution(vector<unsigned char> right48)
{
	unsigned char  sbox[8][4][16] = {
		14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
		0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
		4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
		15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,	//SBox1

		15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
		3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
		0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
		13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,	//SBox2

		10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
		13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
		13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
		1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,	//SBox3

		7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
		13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
		10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
		3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,	//SBox4

		2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
		14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
		4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
		11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,	//SBox5

		12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
		10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 12, 14, 0, 11, 3, 8,
		9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
		4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,	//SBox6

		4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
		13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
		1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
		6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,	//SBox7

		13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
		1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
		7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
		2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11	//SBox8
	};

	// входной 48-битовый блок делим на 8 6-битных подблоков
	// (потому что всего 8 S-блоков, на вход каждого поступает 6 бит)
	unsigned char a[8][6];
	for (int i = 0; i < 8; i++)
	{
		for (int j = 0; j < 6; j++)
		{
			a[i][j] = right48[i * 6 + j];
		}
	}

	int g = 0; // индексатор, куда записывать очередные 4 бита, полученные на основе S-блоков
	vector<unsigned char> res(32);

	for (int i = 0; i < 8; i++)
	{
		// далее хитрым образом определяется элемент S-блока
		// объединятся биты 1 и 6 - получаем номер строки таблицы
		int str = a[i][0] * 2 + a[i][5];

		// объединяются биты со 2 по 5 - столбец таблицы
		int column = 0;
		int pow2 = 8;
		for (int j = 0; j < 4; j++)
		{
			column += a[i][j + 1] * pow2;
			pow2 /= 2;
		}

		// получаем значение из таблиц (S-блоков)
		int sValue = sbox[i][str][column];

		// потом полученное значение переводим в двоичный вид
		int sValueBin[4];
		for (int j = 4; j; j--)
		{
			sValueBin[j - 1] = sValue % 2;
			sValue /= 2;
		}

		// ну и записываем полученное значение к выходному блоку
		for (int j = 0; j < 4; j++)
		{
			res[g] = sValueBin[j];
			g++;
		}
	}

	return res;
}

// ещё одна перестановка
vector<unsigned char> DESCoder::_permutation(vector<unsigned char> right32)
{
	unsigned char per[] = {
		16, 7, 20, 21, 29, 12, 28, 17,
		1, 15, 23, 26, 5, 18, 31, 10,
		2, 8, 24, 14, 32, 27, 3, 9,
		19, 13, 30, 6, 22, 11, 4, 25
	};

	vector<unsigned char> permutated(32);
	for (int i = 0; i < 32; i++)
		permutated[i] = right32[per[i] - 1];

	return permutated;
}

// далее идут вспомогательные функции перевода
// из бит в байты и обратно,
// и то же самое для массивов

// представление одного байта в виде массива бит
vector<unsigned char> DESCoder::_byteToBits(unsigned char byte)
{
	vector<unsigned char> res(8);
	int i = 0;
	while (byte > 0)
	{
		res[i] = byte % 2;
		i++;
		byte /= 2;
	}
	return res;
}

// представление массива байт в виде массива бит
vector<unsigned char> DESCoder::_bytesArrayToBits(vector<unsigned char> bytes)
{
	vector<unsigned char> res;
	for (int i = 0; i < bytes.size(); i++)
	{
		// временный вектор, куда будет записаны биты очередного байта
		vector<unsigned char> iByteBits = _byteToBits(bytes[i]);

		// "приклеиваем" очередную порцию бит к уже полученным
		res.insert(res.end(), iByteBits.begin(), iByteBits.end());
	}
	return res;
}

// представление массива бит в виде байта
unsigned char DESCoder::_bitsToByte(vector<unsigned char> bits)
{
	unsigned char res = 0;
	unsigned char pow2 = 1; // степень 2, на которую необходимо умножать очередной бит
	for (int i = 0; i < bits.size(); i++)
	{
		res += bits[i] * pow2;
		pow2 *= 2;
	}

	return res;
}

// представление массива бит в ввиде массива байт
vector<unsigned char> DESCoder::_bitesArrayToBytes(vector<unsigned char> bites)
{
	vector<unsigned char> res;
	for (int i = 0; i < bites.size() / 8; i++)
	{
		vector<unsigned char> iBits;
		iBits.insert(iBits.end(), bites.begin() + i * 8, bites.begin() + i * 8 + 8);
		unsigned char iByte = _bitsToByte(iBits);
		res.push_back(iByte);
	}
	return res;
}


vector<unsigned char> readFile(ifstream &inputFile)
{
	vector<unsigned char> buffer((std::istreambuf_iterator<char>(inputFile)), (std::istreambuf_iterator<char>()));
	return buffer;
}

int main(int argc, char* argv[])
{
	if (argc < 4)
	{
		cout << "Error: Too few arguments. <input_file> <key_file> { -e | -d } <output_file>" << endl;
		return 0;
	}

	ifstream DesFile(argv[1], ios::binary);
	if (!DesFile)
	{
		cout << "Error: Unable to open file " << argv[1] << endl;
		return 0;
	}

	ifstream KeyFile(argv[2], ios::binary);
	if (!KeyFile)
	{
		cout << "Error: Unable to open file " << argv[2] << endl;
		return 0;
	}

	string operation(argv[3]);

	if (operation != "-e" && operation != "-d")
	{
		cout << "Error: Wrong operation." << endl;
		return 0;
	}

	vector<unsigned char> inputDes = readFile(DesFile);
	vector<unsigned char> inputKey = readFile(KeyFile);

	DESCoder des(inputKey);

	vector<vector <unsigned char> > input;
	vector<vector <unsigned char> > output;

	while (inputDes.size() % 8 != 0)
	{
		inputDes.push_back(0x00);
	}

	int j = 0;
	for (size_t i = 0; i < inputDes.size() / 8; i++)
	{
		vector<unsigned char> tmp;
		for (size_t i = 0; i < 8; i++)
		{
			tmp.push_back(inputDes[j]);
			++j;
		}
		input.push_back(tmp);
	}

	if (operation == "-e")
	{
		for (size_t i = 0; i < input.size(); i++)
		{
			output.push_back(des.encode(input[i]));
		}
	}

	if (operation == "-d")
	{
		for (size_t i = 0; i < input.size(); i++)
		{
			output.push_back(des.decode(input[i]));
		}
	}

	vector<unsigned char> outputDes;

	for (size_t i = 0; i < output.size(); i++)
	{
		for (size_t j = 0; j < output[i].size(); j++)
		{
			outputDes.push_back(output[i][j]);
		}
	}

	while (outputDes[outputDes.size() - 1] == 0x00)
	{
		outputDes.pop_back();
	}


	ofstream outputFile(argv[4], ios::binary);

	for (size_t i = 0; i < outputDes.size(); i++)
	{
		outputFile << static_cast<unsigned char>(outputDes[i]);
	}

	outputFile.close();
	return 0;
}

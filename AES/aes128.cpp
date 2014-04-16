#include <stdio.h>
#include <string>
#include <stdlib.h>

// KEY LENGTH
#define KEY_LENGTH 16
// KEY LENGTH
static unsigned char GF[4][4] = { { 0x02, 0x03, 0x01, 0x01 }, { 0x01, 0x02, 0x03, 0x01 }, { 0x01, 0x01, 0x02, 0x03 }, { 0x03, 0x01, 0x01, 0x02 } };
static unsigned char RGF[4][4] = { { 0x0e, 0x0b, 0x0d, 0x09 }, { 0x09, 0x0e, 0x0b, 0x0d }, { 0x0d, 0x09, 0x0e, 0x0b }, { 0x0b, 0x0d, 0x09, 0x0e } };
static unsigned char RCON[4][10] =
{
	{ 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 },
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
};
// Sbox AND Reverse Sbox
static unsigned char Sbox[KEY_LENGTH][KEY_LENGTH] =
{
	{ 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76 },
	{ 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0 },
	{ 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15 },
	{ 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75 },
	{ 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84 },
	{ 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF },
	{ 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8 },
	{ 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2 },
	{ 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73 },
	{ 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB },
	{ 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79 },
	{ 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08 },
	{ 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A },
	{ 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E },
	{ 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF },
	{ 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 }
};

static unsigned char RSbox[KEY_LENGTH][KEY_LENGTH] =
{
	{ 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB },
	{ 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB },
	{ 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E },
	{ 0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25 },
	{ 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92 },
	{ 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84 },
	{ 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06 },
	{ 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B },
	{ 0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73 },
	{ 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E },
	{ 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B },
	{ 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4 },
	{ 0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F },
	{ 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF },
	{ 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61 },
	{ 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D }
};

typedef struct AESalgo{

private:
	unsigned int rconIndex = 0;
	unsigned char cipherKey[4][4];
	unsigned char cipherkeyTemp[4][4];
	unsigned char inputArray[4][4];
	enum { forward, reverse };

	char fw_mul(unsigned char a, unsigned char b){
		unsigned char p = 0;
		unsigned char counter;
		_Uint32t hi_bit_set;

		for (counter = 0; counter < 8; counter++){
			if ((b & 1) == 1){
				p ^= a;
			}
			hi_bit_set = (a & 0x80);
			a <<= 1;

			if (hi_bit_set == 0x80){
				a ^= 0x1b;
			}

			b >>= 1;
		}
		return p;
	}

	void mulMatrix(int(*matrix1)[4], int(*matrix2)[4], int(*output)[4]){
		for (int i = 0; i < 4; i++){
			for (int j = 0; j < 4; j++){
				for (int x = 0; x < 4; x++)
					output[i][j] += matrix1[i][x] * matrix2[x][j];
			}
		}
	}

	//----------------------- CONVERT CHAR TO HEX, HEX TO CHAR -----------------------

	void charToHex(unsigned char ch, int* hex){
		static unsigned char saucHex[] = "0123456789ABCDEF";
		hex[0] = ((int)saucHex[ch >> 4]) - 48;
		hex[1] = ((int)saucHex[ch & 0xF]) - 48;
		if (hex[0] > 10){
			hex[0] -= 7;
		}
		if (hex[1] > 10){
			hex[1] -= 7;
		}
	}

	void hexToBinary(unsigned char ch, int* binary){
		int hex[2] = { 0, };
		charToHex(ch, hex);
		*binary = hex[0] * 16 + hex[1];
	}

	void binaryToHex(unsigned char ch, int* binary){

	}


	//-------------------------------- ADD ROUNDKEY ----------------------------------

	void addRoundKey(){

		//		printf("AddRound Key :\n");
		for (int i = 0; i < 4; i++){
			for (int j = 0; j < 4; j++){
				int input[4];
				int key[4];
				hexToBinary(inputArray[j][i], &input[j]);
				hexToBinary(cipherKey[j][i], &key[j]);
				inputArray[j][i] = input[j] ^ key[j];
			}
		}
	}



	//---------------------------------- AXPENDKEY -----------------------------------

	void expendKey(){

		//		printf("Expend Key :\n");
		char rotWord[4] = { 0, };
		rotWord[0] = cipherKey[1][3];
		rotWord[1] = cipherKey[2][3];
		rotWord[2] = cipherKey[3][3];
		rotWord[3] = cipherKey[0][3];


		for (int i = 0; i < 4; i++){
			int check[2];
			charToHex(rotWord[i], check);
			rotWord[i] = Sbox[check[0]][check[1]];
		}

		for (int i = 0; i < 4; i++){
			if (i == 0){
				for (int j = 0; j < 4; j++){
					int key[4];
					int rcon[4];
					int rot[4];
					hexToBinary(cipherKey[j][0], &key[j]);
					hexToBinary(RCON[j][rconIndex], &rcon[j]);
					hexToBinary(rotWord[j], &rot[j]);

					cipherKey[j][0] = key[j] ^ rot[j] ^ rcon[j];
				}
				rconIndex++;
			}
			else{
				for (int j = 0; j < 4; j++){
					int key[4];
					int before[4];
					hexToBinary(cipherKey[j][i], &key[j]);
					hexToBinary(cipherKey[j][i - 1], &before[j]);
					cipherKey[j][i] = key[j] ^ before[j];
				}
			}
		}
	}



	//---------------------- CONVERT INPUT CHAR TO ARRAY[4][4] -----------------------

	int inputToArray(unsigned char *input){

		for (int i = 0; i < 4; i++){
			inputArray[0][i] = input[i * 4];
			inputArray[1][i] = input[i * 4 + 1];
			inputArray[2][i] = input[i * 4 + 2];
			inputArray[3][i] = input[i * 4 + 3];
		}
		return 1;
	}

	int arrayToInt(unsigned char *input){
		for (int i = 0; i < 4; i++){
			input[i * 4] = inputArray[0][i];
			input[i * 4 + 1] = inputArray[1][i];
			input[i * 4 + 2] = inputArray[2][i];
			input[i * 4 + 3] = inputArray[3][i];
		}
		return 1;
	}



	//--------------------------------- SUBSTITUTE BYTE ------------------------------


	void subStituteByte(unsigned char(*SBox)[16]){
		//		printf("SubStitute Byte :\n");
		for (int i = 0; i < 4; i++){
			for (int j = 0; j < 4; j++){
				int check[2];
				charToHex(inputArray[i][j], check);
				inputArray[i][j] = SBox[check[0]][check[1]];
			}
		}

	}

	//	void AES(void(AESalgo::*SByte)(void)){
	//		(this->*SByte)();
	//	}

	//------------------------------------- SHIFT ROW --------------------------------

	void shiftsRows(int direction){
		//		printf("Shifts Rows :\n");
		if (direction == forward){
			int index = direction + 2;
			unsigned char temp = inputArray[index - 1][0];
			inputArray[index - 1][0] = inputArray[index - 1][1];
			inputArray[index - 1][1] = inputArray[index - 1][2];
			inputArray[index - 1][2] = inputArray[index - 1][3];
			inputArray[index - 1][3] = temp;

			temp = inputArray[index][0];
			inputArray[index][0] = inputArray[index][2];
			inputArray[index][2] = temp;
			temp = inputArray[2][1];
			inputArray[index][1] = inputArray[index][3];
			inputArray[index][3] = temp;

			temp = inputArray[index + 1][0];
			inputArray[index + 1][0] = inputArray[index + 1][3];
			inputArray[index + 1][3] = inputArray[index + 1][2];
			inputArray[index + 1][2] = inputArray[index + 1][1];
			inputArray[index + 1][1] = temp;

		}
		else if (direction == reverse){
			int index = direction + 1;
			unsigned char temp = inputArray[index + 1][0];
			inputArray[index + 1][0] = inputArray[index + 1][1];
			inputArray[index + 1][1] = inputArray[index + 1][2];
			inputArray[index + 1][2] = inputArray[index + 1][3];
			inputArray[index + 1][3] = temp;

			temp = inputArray[index][0];
			inputArray[index][0] = inputArray[index][2];
			inputArray[index][2] = temp;
			temp = inputArray[2][1];
			inputArray[index][1] = inputArray[index][3];
			inputArray[index][3] = temp;

			temp = inputArray[index - 1][0];
			inputArray[index - 1][0] = inputArray[index - 1][3];
			inputArray[index - 1][3] = inputArray[index - 1][2];
			inputArray[index - 1][2] = inputArray[index - 1][1];
			inputArray[index - 1][1] = temp;
		}

	}



	//---------------------------------- MIX COLUMNS ---------------------------------

	void mixColumns(unsigned char(*table)[4]){
		//		printf("Mix Columns :\n");
		unsigned char st[4][4];
		_Uint32t c = 0;

		for (c = 0; c < 4; c++){
			st[0][c] = fw_mul(inputArray[0][c], table[0][0]) ^ fw_mul(inputArray[1][c], table[0][1]) ^ fw_mul(inputArray[2][c], table[0][2]) ^ fw_mul(inputArray[3][c], table[0][3]);
			st[1][c] = fw_mul(inputArray[0][c], table[1][0]) ^ fw_mul(inputArray[1][c], table[1][1]) ^ fw_mul(inputArray[2][c], table[1][2]) ^ fw_mul(inputArray[3][c], table[1][3]);
			st[2][c] = fw_mul(inputArray[0][c], table[2][0]) ^ fw_mul(inputArray[1][c], table[2][1]) ^ fw_mul(inputArray[2][c], table[2][2]) ^ fw_mul(inputArray[3][c], table[2][3]);
			st[3][c] = fw_mul(inputArray[0][c], table[3][0]) ^ fw_mul(inputArray[1][c], table[3][1]) ^ fw_mul(inputArray[2][c], table[3][2]) ^ fw_mul(inputArray[3][c], table[3][3]);
		}

		memcpy(inputArray, st, 16);
	}

	void countExpendKey(int val){
		memcpy(cipherKey, cipherkeyTemp, 16);
		for (int i = 0; i < val; i++){
			expendKey();
		}
		rconIndex = 0;
	}

	void initialize(unsigned char(*input)[4], unsigned char(*key)[4]){
		unsigned char temp_in[4][4] = {0,};
		unsigned char temp_key[4][4] = { 0, };

		memcpy(temp_in, input, 16);
		memcpy(temp_key, key, 16);

		for (int i = 0; i < 4; i++){
			inputArray[0][i] = temp_in[i][0];
			inputArray[1][i] = temp_in[i][1];
			inputArray[2][i] = temp_in[i][2];
			inputArray[3][i] = temp_in[i][3];

			cipherKey[0][i] = temp_key[i][0];
			cipherKey[1][i] = temp_key[i][1];
			cipherKey[2][i] = temp_key[i][2];
			cipherKey[3][i] = temp_key[i][3];
			
			cipherkeyTemp[0][i] = temp_key[i][0];
			cipherkeyTemp[1][i] = temp_key[i][1];
			cipherkeyTemp[2][i] = temp_key[i][2];
			cipherkeyTemp[3][i] = temp_key[i][3];
		}

		rconIndex = 0;
	}

	void initialize(unsigned char *input, unsigned char *key){

		inputToArray(input);
		setKey(key);
		rconIndex = 0;
	}

	//-------------------------- INITIALIZE AES STRUCT BY KEY ------------------------

	void setKey(unsigned char *key){

		for (int i = 0; i < 4; i++){
			cipherKey[0][i] = key[i * 4];
			cipherKey[1][i] = key[i * 4 + 1];
			cipherKey[2][i] = key[i * 4 + 2];
			cipherKey[3][i] = key[i * 4 + 3];

			cipherkeyTemp[0][i] = key[i * 4];
			cipherkeyTemp[1][i] = key[i * 4 + 1];
			cipherkeyTemp[2][i] = key[i * 4 + 2];
			cipherkeyTemp[3][i] = key[i * 4 + 3];
		}
	}

	void finalize(unsigned char(*result)[4]){
		
		for (int i = 0; i < 4; i++){
			result[i][0] = inputArray[0][i];
			result[i][1] = inputArray[1][i];
			result[i][2] = inputArray[2][i];
			result[i][3] = inputArray[3][i];
		}
		memcpy(inputArray,result,16);
	}

	void finalize(unsigned char *result){
		arrayToInt(result);
	}
public:



	//--------------------------------- AES ENCODE LOOP ------------------------------

	int encodeAES(unsigned char *input, unsigned char *key, unsigned char *result){

		initialize(input, key);

		displayAll();

		addRoundKey();

		for (int i = 0; i < 9; i++){
			subStituteByte(Sbox);
			shiftsRows(forward);
			mixColumns(GF);

			expendKey();
			addRoundKey();
		}

		subStituteByte(Sbox);
		shiftsRows(forward);

		expendKey();
		addRoundKey();
		displayAll();

		finalize(result);
		displayAll();
		return 1;
	}

	int encodeAES(unsigned char(*input)[4], unsigned char(*key)[4], unsigned char(*result)[4]){

		initialize(input,key);
		displayAll(0);
		addRoundKey();
		displayAll(1);

		for (int i = 0; i < 9; i++){
			subStituteByte(Sbox);
			displayAll(i + 2);
			shiftsRows(forward);
			displayAll(i + 2);
			mixColumns(GF);
			displayAll(i + 2);

			expendKey();
			displayAll(i + 2);
			addRoundKey();
			displayAll(i + 2);
		}

		subStituteByte(Sbox);
		displayAll(10);
		shiftsRows(forward);
		displayAll(10);

		expendKey();
		displayAll(10);
		addRoundKey();
		displayAll(10);
		finalize(result);
		displayAll(10);

		return 1;
	}

	//--------------------------------- AES DENCODE LOOP -----------------------------

	int decodeAES(unsigned char *input, unsigned char *key, unsigned char *result){
		int count = 10;
		initialize(input, key);
		displayAll();

		countExpendKey(count--);

		addRoundKey();
		shiftsRows(reverse);
		subStituteByte(RSbox);
		countExpendKey(count--);

		addRoundKey();

		for (int i = 0; i < 8; i++){

			mixColumns(RGF);
			shiftsRows(reverse);
			subStituteByte(RSbox);

			countExpendKey(count--);
			addRoundKey();
		}
		mixColumns(RGF);
		shiftsRows(reverse);
		subStituteByte(RSbox);

		countExpendKey(count--);
		addRoundKey();


		finalize(result);
		displayAll();

		return 1;
	}

	int decodeAES(unsigned char(*input)[4], unsigned char(*key)[4], unsigned char(*result)[4]){

		int count = 10;

		initialize(input, key);

		displayAll();

		countExpendKey(count--);

		addRoundKey();
		shiftsRows(reverse);
		subStituteByte(RSbox);
		countExpendKey(count--);

		addRoundKey();

		for (int i = 0; i < 8; i++){

			mixColumns(RGF);
			shiftsRows(reverse);
			subStituteByte(RSbox);

			countExpendKey(count--);
			addRoundKey();
		}
		mixColumns(RGF);
		shiftsRows(reverse);
		subStituteByte(RSbox);

		countExpendKey(count--);
		addRoundKey();

		displayAll();

		finalize(result);
		displayAll();
		return 1;
	}

	//------------------------------ DISPLAY ARRAY STATUS ----------------------------
	void displayAll(int line){
		displayLine(line);
		display();
		displayKey();
	}


	void displayAll(){
		displayLine(0);
		display();
		displayKey();
	}

	void display(){
		for (int i = 0; i<4; i++){
			for (int j = 0; j<4; j++){
				printf("%02X ", inputArray[i][j]);
			}
		}
		printf("\n");
	}

	void displayKey(){
		for (int i = 0; i<4; i++){
			for (int j = 0; j<4; j++){
				printf("%02X ", cipherKey[i][j]);
			}
		}
		printf("\n");
	}
	void displayLine(int line){
		printf("---------------------------- %d -----------------------------\n", line);
	}




} AES;


int main(){
	unsigned char inputArray[4][4] = { { 0x32, 0x43, 0xf6, 0xa8 }, { 0x88, 0x5a, 0x30, 0x8d }, { 0x31, 0x31, 0x98, 0xa2 }, { 0xe0, 0x37, 0x07, 0x34 } };
	unsigned char cipherKey[4][4] = { { 0x2b, 0x7e, 0x15, 0x16 }, { 0x28, 0xae, 0xd2, 0xa6 }, { 0xab, 0xf7, 0x15, 0x88 }, { 0x09, 0xcf, 0x4f, 0x3c }, };
	unsigned char resultArray[4][4];
	AES a;
	a.encodeAES(inputArray, cipherKey, resultArray);
	a.decodeAES(resultArray, cipherKey, inputArray);
	return 0;
}
/******************************************************************************** RFID ********************************************************************************/
#include <SPI.h>
#include <MFRC522.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <Arduino.h>

#define SS_PIN          21          // Configurable, see typical pin layout above
#define RST_PIN         22          // Configurable, see typical pin layout above

typedef uint64_t bit64;

MFRC522 mfrc522(SS_PIN, RST_PIN);   // Create MFRC522 instance.

MFRC522::MIFARE_Key key;

String readData="";
byte blockAddr;
bool flag = false;

/*** Helper routine to dump a byte array as hex values to Serial. */
void dump_byte_array(byte *buffer, byte bufferSize) {
    for (byte i = 0; i < bufferSize; i++) {
        Serial.print(buffer[i] < 0x10 ? " 0" : " ");
        Serial.print(buffer[i], HEX);
    }
}

/******************************************************************************** Akhir RFID ********************************************************************************/

/******************************************************************************** Fungsi enkrip dan dekrip ********************************************************************************/

bit64 constants[16] = {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f};

bit64 state[5] = { 0 }, t[5] = { 0 };

bit64 rotate(bit64 x, int l){ // rotate function
  bit64 temp;
  temp = (x >> l) ^ (x << (64-l)); // shifting bit
  return temp;
}

bit64 string_to_hex(char* str) {
  bit64 num = 0;
  int len = strlen(str);
  
  for (int i = 0; i < len; i++) {
    num = num << 4; // shift kiri 4 bit
    if (str[i] >= '0' && str[i] <= '9') {
      num += str[i] - '0';
    } else if (str[i] >= 'a' && str[i] <= 'f') {
      num += str[i] - 'a' + 10;
    } else if (str[i] >= 'A' && str[i] <= 'F') {
      num += str[i] - 'A' + 10;
    }
  }

  return num;
}

// Menampilkan state
void print_state(bit64 state[5]){
  for (int i = 0; i < 5; i++)
  {
    Serial.println(state[i]);
  }
}


void linear(bit64 state[5]){
  bit64 temp0, temp1;

  temp0 = rotate(state[0], 19);
  temp1 = rotate(state[0], 28);
  state[0] = state[0] ^ temp0 ^ temp1;
  
  temp0 = rotate(state[1], 61);
  temp1 = rotate(state[1], 39);
  state[1] = state[1] ^ temp0 ^ temp1;

  temp0 = rotate(state[2], 1);
  temp1 = rotate(state[2], 6);
  state[2] = state[2] ^ temp0 ^ temp1;

  temp0 = rotate(state[3], 10);
  temp1 = rotate(state[3], 17);
  state[3] = state[3] ^ temp0 ^ temp1;

  temp0 = rotate(state[4], 7);
  temp1 = rotate(state[4], 41);
  state[4] = state[4] ^ temp0 ^ temp1;
}

void sbox(bit64 x[5]){ // substitution with bit slicing
  x[0] ^= x[4]; x[4] ^= x[3]; x[2] ^= x[1];
  t[0] = x[0]; t[1] = x[1]; t[2] = x[2]; t[3] = x[3]; t[4] = x[4];
  t[0] = ~t[0]; t[1] = ~t[1]; t[2] = ~t[2]; t[3] = ~t[3]; t[4] = ~t[4];
  t[0] &= x[1]; t[1] &= x[2]; t[2] &= x[3]; t[3] &= x[4]; t[4] &= x[0];
  x[0] ^= t[1]; x[1] ^= t[2]; x[2] ^= t[3]; x[3] ^= t[4]; x[4] ^= t[0];
  x[1] ^= x[0]; x[0] ^= x[4]; x[3] ^= x[2]; x[2] = ~x[2];
}

void add_constant(bit64 state[5], int i, int a){
  state[2] = state[2] ^ constants[12-a+i];
}

void initialization(bit64 state[5], bit64 key[2]){
  p(state, 12);
  state[3] = state[3] ^ key[0];
  state[4] = state[4] ^ key[1];
}

void p(bit64 state[5], int a){
  for (int i = 0; i < a; i++)
  {
    add_constant(state, i, a);
    sbox(state);
    linear(state);
  }
}

void encrypt(bit64 state[5], int length, bit64 plaintext[], bit64 ciphertext[]){ // length = jumlah plain text
  ciphertext[0] = plaintext[0] ^ state[0];
  for (int i = 1; i < length; i++)
  {
    p(state, 6);
    ciphertext[i] =  plaintext[i] ^ state[0];
    state[0] = ciphertext[i];
  }
}

void decrypt(bit64 state[5], int length, bit64 plaintext[], bit64 ciphertext[]){ // length = jumlah plain text
  plaintext[0] = state[0] ^ ciphertext[0];
  state[0] = ciphertext[0];
  for (int i = 1; i < length; i++)
  {
    p(state, 6);
    plaintext[i] =  state[0] ^ ciphertext[i];
    state[0] = ciphertext[i];
  }
}

void finalization(bit64 state[5], bit64 key[2]){
  state[0] = state[0] ^ key[0];
  state[1] = state[1] ^ key[1];
  p(state, 12);
  state[3] = state[3] ^ key[0];
  state[4] = state[4] ^ key[1];
}

bit64 message_to_hex(char *message) {
    // convert message to hexadecimal uint64_t
    uint64_t num = 0;
    int len = strlen(message);
    int shift = 0;
    for (int i = len - 1; i >= 0; i--) {
        num |= ((uint64_t)message[i] << shift);
        shift += 8;
    }
    return num;
}

char *hex_to_message(uint64_t num) {
    // convert hexadecimal uint64_t to message
    int len = 1;
    uint64_t temp = num;
    while (temp >>= 8) len++;
    char *message =(char*) malloc((len + 1)*sizeof(char));
    message[len] = '\0';
    for (int i = len - 1; i >= 0; i--) {
        message[i] = (char)(num & 0xff);
        num >>= 8;
    }
    return message;
}

char sandi[100];
char password[100] = {"ppmc"};
char dekrippass[100];

void enkrip(char* password){
  bit64 nonce[2] = { 0 };
  bit64 key[2] = { 0x1223931931, 0x1231942321 };
  bit64 IV = 0x80400c0600000000;
  bit64 ciphertext[2] = { 0 };

  bit64 plaintext[] = {message_to_hex(password)};

  state[0] = IV;
  state[1] = key[0];
  state[2] = key[1];
  state[3] = nonce[0];
  state[4] = nonce[1];

  initialization(state, key);
  encrypt(state, 1, plaintext, ciphertext);
  finalization(state, key);
  // Serial.println(ciphertext[0]);
  strcpy(password, hex_to_message(ciphertext[0]));
}

void dekrip(bit64 terenkrip, char* cpy){
  bit64 nonce[2] = { 0 };
  bit64 key[2] = { 0x1223931931, 0x1231942321 };
  bit64 IV = 0x80400c0600000000;

  bit64 ciphertextdecrypt[] = {terenkrip};
  bit64 plaintextdecrypt[2] = { 0 };

  state[0] = IV;
  state[1] = key[0];
  state[2] = key[1];
  state[3] = nonce[0];
  state[4] = nonce[1];

  initialization(state, key);

  decrypt(state, 1, plaintextdecrypt, ciphertextdecrypt);
  finalization(state, key);
  // Serial.println(plaintextdecrypt[0]);
  strcpy(cpy, hex_to_message(plaintextdecrypt[0]));

}

/******************************************************************************** Akhir fungsi enkrip dan dekrip ********************************************************************************/

// Define the pin number for the LED
#define LED_PIN1 32
#define LED_PIN2 25

void setup() {
  // Set the LED pin as an output
  pinMode(LED_PIN1, OUTPUT);
  pinMode(LED_PIN2, OUTPUT);
  
  // Init SPI bus
  SPI.begin();
  Serial.begin(115200);
  
  // Init MFRC522 card
  mfrc522.PCD_Init(); 
  
  // Prepare the key (used both as key A and as key B)
  // using FFFFFFFFFFFFh which is the default at chip delivery from the factory
  for (byte i = 0; i < 6; i++) {
      key.keyByte[i] = 0xFF;
  }
}

void loop() {
  while(!flag){
    // Reset the loop if no new card present on the sensor/reader. This saves the entire process when idle.
    if ( ! mfrc522.PICC_IsNewCardPresent())
        return;

    // Select one of the cards
    if ( ! mfrc522.PICC_ReadCardSerial())
        return;

    MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);

    // Check for compatibility
    if (    piccType != MFRC522::PICC_TYPE_MIFARE_MINI
        &&  piccType != MFRC522::PICC_TYPE_MIFARE_1K
        &&  piccType != MFRC522::PICC_TYPE_MIFARE_4K) {
        Serial.println(F("This sample only works with MIFARE Classic cards."));
        return;
    }

    // In this sample we use the second sector,
    // that is: sector #1, covering block #4 up to and including block #7
    MFRC522::StatusCode status;
    byte buffer[18];
    byte size = sizeof(buffer);
    byte sector  = 2;
    byte blockNo = 0;

    byte trailerBlock = (sector*4) + 3;
    status = (MFRC522::StatusCode) mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));

    blockAddr = 8;
    status = (MFRC522::StatusCode) mfrc522.MIFARE_Read(blockAddr, buffer, &size);
    String sTemp = String((char*)buffer);
    readData += sTemp.substring(0,16);
    
    const char* charArr = readData.c_str();

    strcpy(sandi, charArr);

    // Halt PICC
    mfrc522.PICC_HaltA();
    // Stop encryption on PCD
    mfrc522.PCD_StopCrypto1();

    flag = true;
  }

  dekrip(message_to_hex(sandi), sandi);
  dekrip(message_to_hex(password), dekrippass);

  strcpy(password, "ppmc");
  
  if(!strcmp(sandi, dekrippass)){
    // Turn the LED on
    Serial.println("Akses diterima. Silakan!");
    digitalWrite(LED_PIN1, HIGH); delay(1000);
    digitalWrite(LED_PIN1, LOW); delay(1000);
    digitalWrite(LED_PIN1, HIGH); delay(1000);
    digitalWrite(LED_PIN1, LOW); delay(1000);
    digitalWrite(LED_PIN1, HIGH); delay(1000);
    digitalWrite(LED_PIN1, LOW); delay(1000);
    readData="";
    strcpy(sandi,"");
    strcpy(dekrippass,"");
    flag=false;
  } else {
    Serial.println("Akses ditolak");
    // Turn the LED on
    digitalWrite(LED_PIN2, HIGH);delay(1000);
    digitalWrite(LED_PIN2, LOW);delay(1000);
    digitalWrite(LED_PIN2, HIGH);delay(1000);
    digitalWrite(LED_PIN2, LOW);delay(1000);
    digitalWrite(LED_PIN2, HIGH);delay(1000);
    digitalWrite(LED_PIN2, LOW);delay(1000);
    readData="";
    strcpy(sandi,"");
    strcpy(dekrippass,"");
    flag=false;

  }
}

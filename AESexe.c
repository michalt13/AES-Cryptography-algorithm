
#include <stdio.h>

#include "conf_example.h"
#include "crypt.h"
#include "AESexe.h"
#include "delay.h"



/** Global Variable declaration **/

/* Key Initialization vector */
uint8_t key_vectors[]
= {0x2b, 0x7e, 0x15, 0x16};

/*  Initialization vector
* Note: AES Standard FIPS SP800-38A provides detailed explanation
* on generation of init_vector for different CFB modes
*/
#if (AES_CBC == true) | (AES_CFB == true) | (AES_OFB == true)

uint8_t init_vector[]
= {0x00, 0x01, 0x02, 0x03};

#endif

/* Input plain text data that are to be encrypted */
// uint8_t pText[] = {"Input_Text_blck1Input_Text_blck2Input_Text_blck3Input_Text_blck4"};
/* array to store the encrypted message */
uint8_t cText[32] = {0};
/* array to store the decrypted message */
uint8_t pText1[8];

/*!
* \brief Main application function.                              \n
* -> Initialize USART0 for print functions                       \n
* -> Initialize AES to generate Key schedule for AES-128         \n
* -> Based on the AES mode enabled in conf_example.h file,       \n
*    execute encryption and decryption of a message and          \n
*    compare them against input data to check its functionality. \n
* -> The decrypted message can be viewed on the COM port terminal \n
*/
int AESmain(void)
{
	/* Initializes MCU, drivers and middleware */


	/* Generate key schedule for AES-128 from the Cipher Key */
	aes_init(key_vectors);

	/* Print status messages */
	printf("AES key generated successfully!..\r\n");

	/* Print Input message for user */
	printf("\n The message to be encrypted is:\r\n");
	//printf("\n %s \r\n", pText);

	/*
	* Perform ECB, CFB, OFB, CTR and CBC Encryption and Decryption
	* based on the mode enabled in conf_example.h. User can choose
	* the mode that he wants to evaluate. By default, all modes are
	* enabled.
	* The decrypted message is printed to USART0.
	* If the decrypted message is same as the input plain text,
	* it ensures the working of each mode.
	*/
	while (1)
	{
		
		uint8_t pText[] =  {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
		delay_ms(100);


		#if (AES_ECB == true)

		// Perform ECB Encryption
		ecb_encrypt(pText, cText, sizeof(pText));
		for (volatile int i = 0; i < 1000; i++)
		;
		// Perform ECB Decryption
		ecb_decrypt(cText, pText1, sizeof(cText));
		// Print decrypted message
		//	printf("\r\nECB %s", pText);
		//	printf("\r\nECB %s", cText);
		//	printf("\r\nECB %s", pText1);
		printf("\r\nECB =");
		for(uint8_t i = 0; i < sizeof(pText); i++)
		{
			printf("%02x,",pText[i]);
		}
		printf("\r\nECB =");
		for(uint8_t i = 0; i < sizeof(cText); i++)
		{
			printf("%02x,",cText[i]);
		}
		printf("\r\nECB =");
		for(uint8_t i = 0; i < sizeof(pText1); i++)
		{
			printf("%02x,",pText1[i]);
		}

		#endif

		#if (AES_CFB == true)

		// Perform CFB Encryption
		cfb_encrypt(pText, cText, init_vector, CFB_MODE_8, sizeof(pText));
		for (volatile int i = 0; i < 1000; i++)
		;
		// Perform CFB Decryption
		cfb_decrypt(cText, pText1, init_vector, CFB_MODE_8, sizeof(cText));
		// Print decrypted message
		//		printf("\r\nCFB %s", pText);
		//		printf("\r\nCFB %s", cText);
		//		printf("\r\nCFB %s", pText1);
		
		printf("\r\nCFB =");
		for(uint8_t i = 0; i < sizeof(pText); i++)
		{
			printf("%02x,",pText[i]);
		}
		printf("\r\nCFB =");
		for(uint8_t i = 0; i < sizeof(cText); i++)
		{
			printf("%02x,",cText[i]);
		}
		printf("\r\nCFB =");
		for(uint8_t i = 0; i < sizeof(pText1); i++)
		{
			printf("%02x,",pText1[i]);
		}

		#endif

		#if (AES_OFB == true)

		// Perform OFB Encryption
		ofb_encrypt(pText, cText, init_vector, sizeof(pText));
		for (volatile int i = 0; i < 1000; i++)
		;
		// Perform OFB Decryption
		ofb_encrypt(cText, pText1, init_vector, sizeof(cText));
		// Print decrypted message
		//		printf("\r\nOFB %s", pText);
		//		printf("\r\nOFB %s", cText);
		//		printf("\r\nOFB %s", pText1);

		printf("\r\nOFB =");
		for(uint8_t i = 0; i < sizeof(pText); i++)
		{
			printf("%02x,",pText[i]);
		}
		printf("\r\nOFB =");
		for(uint8_t i = 0; i < sizeof(cText); i++)
		{
			printf("%02x,",cText[i]);
		}
		printf("\r\nOFB =");
		for(uint8_t i = 0; i < sizeof(pText1); i++)
		{
			printf("%02x,",pText1[i]);
		}

		#endif

		#if (AES_CTR == true)

		/* Initialize Counter block with initialization vector,
		* nonce and counter value
		*/
		ctr_blk_t counter_vector = {.i_vector = AES_CTR_IVECTOR, .nonce = AES_CTR_NONCE, .counter = AES_CTR_COUNTER};
		// Perform CTR Encryption
		ctr_encrypt_decrypt(pText, cText, &counter_vector, sizeof(pText));
		// Send Counter block value to decryptor
		for (volatile int i = 0; i < 1000; i++)
		;
		counter_vector.i_vector = AES_CTR_IVECTOR;
		counter_vector.nonce    = AES_CTR_NONCE;
		counter_vector.counter  = AES_CTR_COUNTER;
		// Perform CTR Decryption
		ctr_encrypt_decrypt(cText, pText1, &counter_vector, sizeof(pText1));
		// Print decrypted message
		//		printf("\r\nCTR %s", pText);
		//		printf("\r\nCTR %s", cText);
		//		printf("\r\nCTR %s", pText1);


		printf("\r\nCTR =");
		for(uint8_t i = 0; i < sizeof(pText); i++)
		{
			printf("%02x,",pText[i]);
		}
		printf("\r\nCTR =");
		for(uint8_t i = 0; i < sizeof(cText); i++)
		{
			printf("%02x,",cText[i]);
		}
		printf("\r\nCTR =");
		for(uint8_t i = 0; i < sizeof(pText1); i++)
		{
			printf("%02x,",pText1[i]);
		}

		#endif

		/*! \warning CBC mode is done at the last as it process input plain text
		* during encryption and so the plain text value is not retained.
		* For testing purpose, to preserve the input plan text for testing with
		* other modes, this mode is added at the last.
		*/
		#if (AES_CBC == true)

		// Perform CBC Encryption
		cbc_encrypt(pText, cText, init_vector, sizeof(pText));
		for (volatile int i = 0; i < 1000; i++)
		;
		// Perform CBC Decryption
		cbc_decrypt(cText, pText1, init_vector, sizeof(cText));
		// Print decrypted message
		//		printf("\r\nCBC %s", pText);
		//		printf("\r\nCBC %s", cText);
		//		printf("\r\nCBC %s", pText1);


		printf("\r\nCBC =");
		for(uint8_t i = 0; i < sizeof(pText); i++)
		{
			printf("%02x,",pText[i]);
		}
		printf("\r\nCBC =");
		for(uint8_t i = 0; i < sizeof(cText); i++)
		{
			printf("%02x,",cText[i]);
		}
		printf("\r\nCBC =");
		for(uint8_t i = 0; i < sizeof(pText1); i++)
		{
			printf("%02x,",pText1[i]);
		}
		#endif
		printf("\r\n");
	}
	/* Forever loop */
	while (1)
	;
}

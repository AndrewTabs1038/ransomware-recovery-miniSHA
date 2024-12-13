#include "xparameters.h"
#include "xtmrctr.h"
#include "xscugic.h"
#include "xil_exception.h"
#include "xil_printf.h"
#include "xtmrctr_l.h"
#include <stdbool.h>

#define TIMER_DEVICE_ID      XPAR_AXI_TIMER_0_DEVICE_ID
#define INTC_DEVICE_ID       XPAR_SCUGIC_SINGLE_DEVICE_ID
#define TIMER_INTR_ID        XPAR_FABRIC_AXI_TIMER_0_INTERRUPT_INTR
#define MEM_OFFSET        	0x2000
#define XTC_ISR_OFFSET               0x0C
#define XTC_INT_OCCURED_MASK         0x01
#define HASH_TABLE_LENGTH		5

XTmrCtr timer;
XScuGic intCtrl;

bool checkData = false;

unsigned int hashFunction(unsigned int data){
	//MINI SHA1
	unsigned int hash = 0;
	hash ^= ((data >> 16) & 0xFFF);
	hash ^= ((data & 0xFFF) << 4);
	hash = (hash << 3) | (hash >> 9);
	hash ^= 0xABC;
	//to ensure value is within 0xfff and a multiple of 4
	hash &= 0xFFF;
	hash &= ~0x3;
	return hash;
}

void storeHashes (){

	unsigned int hashed;
	unsigned int addr = XPAR_AXI_BRAM_CTRL_2_S_AXI_BASEADDR;

	unsigned int known_malware [HASH_TABLE_LENGTH] = {
			0x1000000b,
			0x1000000d,
			0xdeadbeef,
			0xbabebabe,
			0xf00df00d
	};
	for (int i = 0; i<HASH_TABLE_LENGTH; i++){
		hashed = addr + hashFunction(known_malware[i]);
		Xil_Out32(hashed,1);
	}
}

unsigned int getData(unsigned int addr){
	unsigned int rev0, rev1;

	rev0 = Xil_In32(addr);
	if (rev0 != 0){return rev0;}

	rev1 = Xil_In32(addr + MEM_OFFSET);
	Xil_Out32(addr, rev1);
	return rev1;
}


void storeData(unsigned int data){
	//working memory (BRAM0)
	static unsigned int current_addr = XPAR_AXI_BRAM_CTRL_0_S_AXI_BASEADDR;
	unsigned int hash = hashFunction(data);
	unsigned int hashed = XPAR_AXI_BRAM_CTRL_2_S_AXI_BASEADDR + hash;

	unsigned int rev = Xil_In32(hashed);



	if(rev == 1){xil_printf("MALWARE DETECTED: %x, DATA NOT STORED \n\r", data);}
	else{
		Xil_Out32(current_addr , data);
		current_addr +=4;
	}
}

void printMemory(bool Bram0){
	unsigned int num, data;

	if(Bram0){
		for (num = XPAR_AXI_BRAM_CTRL_0_S_AXI_BASEADDR;
		                 num < XPAR_AXI_BRAM_CTRL_0_S_AXI_HIGHADDR;
		                 num += 4) {

		        data = Xil_In32(num);
		        xil_printf("BRAM0: The data at %x is %x \n\r", num, data);
		    }
	}
	else{
		for (num = XPAR_AXI_BRAM_CTRL_1_S_AXI_BASEADDR;
		                 num < XPAR_AXI_BRAM_CTRL_1_S_AXI_HIGHADDR;
		                 num += 4) {

		        data = Xil_In32(num);
		        xil_printf("BRAM1: The data at %x is %x \n\r", num, data);
		    }

	}
    xil_printf("Print done\n\r");


}


void timerInterruptHandler(void *CallbackRef, u8 TmrCtrNumber) {
    unsigned int rev0;
//    unsigned int rev1;
    unsigned int num;


    for (num = XPAR_AXI_BRAM_CTRL_0_S_AXI_BASEADDR;
         num < XPAR_AXI_BRAM_CTRL_0_S_AXI_HIGHADDR;
         num += 4) {

        rev0 = Xil_In32(num);

        if(rev0 != 0 ){Xil_Out32(num  + MEM_OFFSET, rev0);}

    }


    xil_printf("Transfer Done\n\r");
    checkData = true;
    XTmrCtr *TimerInstance = (XTmrCtr *)CallbackRef;
    XTmrCtr_WriteReg(TimerInstance->Config.BaseAddress, TmrCtrNumber, XTC_ISR_OFFSET, XTC_INT_OCCURED_MASK);
}


int init_system() {
    int Status;

    Status = XTmrCtr_Initialize(&timer, TIMER_DEVICE_ID);
    if (Status != XST_SUCCESS) {
        xil_printf("Failed to initialize Timer\n\r");
        return XST_FAILURE;
    }


    XTmrCtr_SetHandler(&timer, (XTmrCtr_Handler)timerInterruptHandler, &timer);


    XScuGic_Config *IntcConfig = XScuGic_LookupConfig(INTC_DEVICE_ID);
    if (IntcConfig == NULL) {
        xil_printf("Interrupt Controller Lookup Failed\n\r");
        return XST_FAILURE;
    }

    Status = XScuGic_CfgInitialize(&intCtrl, IntcConfig, IntcConfig->CpuBaseAddress);
    if (Status != XST_SUCCESS) {
        xil_printf("Interrupt Controller Initialization Failed\n\r");
        return XST_FAILURE;
    }

    
    XScuGic_SetPriorityTriggerType(&intCtrl, TIMER_INTR_ID, 0xA0, 0x3);

    
    Status = XScuGic_Connect(&intCtrl, TIMER_INTR_ID,
                              (Xil_InterruptHandler)XTmrCtr_InterruptHandler, &timer);
    if (Status != XST_SUCCESS) {
        xil_printf("Failed to Connect Timer Interrupt Handler\n\r");
        return XST_FAILURE;
    }

    
    XScuGic_Enable(&intCtrl, TIMER_INTR_ID);

    
    Xil_ExceptionInit();
    Xil_ExceptionRegisterHandler(XIL_EXCEPTION_ID_INT,
                                 (Xil_ExceptionHandler)XScuGic_InterruptHandler,
                                 &intCtrl);
    Xil_ExceptionEnable();

    
    XTmrCtr_SetOptions(&timer, 0, XTC_INT_MODE_OPTION | XTC_AUTO_RELOAD_OPTION);

    XTmrCtr_SetResetValue(&timer, 0, 1);  // Adjust based on your actual clock frequency

    
    XTmrCtr_Start(&timer, 0);

    return XST_SUCCESS;
}

int main() {

	unsigned int num;
	unsigned int rev;
	unsigned int data_counter = 12;
	unsigned int data_get [15];
	unsigned int data_store [15];

	for (num = 0; num < 15; num++){
		data_get[num] = (unsigned int) 0xA0000000 + data_counter;
		data_counter = data_counter + 4;
	}

	xil_printf("------Begin Test------\n\r");
	data_counter = 21;
	for (num = XPAR_AXI_BRAM_CTRL_1_S_AXI_BASEADDR; num < XPAR_AXI_BRAM_CTRL_1_S_AXI_BASEADDR + 15 * 4;
	         num += 4)
		{
			Xil_Out32(num,  0x10000000 + data_counter);
			rev = Xil_In32(num);

			xil_printf("The data at %x is %x \n\r", num, rev);
			data_counter++;
		}

	for (num = XPAR_AXI_BRAM_CTRL_1_S_AXI_BASEADDR + 60; num < XPAR_AXI_BRAM_CTRL_1_S_AXI_BASEADDR + 70;
		         num += 4)
			{
				Xil_Out32(num,  0x10000000 + data_counter);
				rev = Xil_In32(num);

				xil_printf("The data at %x is %x \n\r", num, rev);
				data_counter++;
			}

    
    if (init_system() != XST_SUCCESS) {
        xil_printf("System Initialization Failed\n\r");
        return XST_FAILURE;
    }


    data_counter = 0;
	for (num = 0; num < 15; num++){
			data_store[num] = 0x10000000 + data_counter;
			data_counter++;
	}

	storeHashes ();
    int size = sizeof(data_store) / sizeof(data_store[0]);

    for (int i = 0; i < size; i++){
    	storeData(data_store[i]);
    }
    printMemory(true);

    while(1){
    	if(checkData){

    		for (int i = 0; i < size; i++){
    			xil_printf("Get Address: %x Data: %x \n\r", data_get[i], getData(data_get[i]));
    		}
    		printMemory(true);
    		checkData = false;
    	}


    }



    return 0;
}

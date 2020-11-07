/*
 * Copyright 2016-2019 NXP
 * All rights reserved.
 *
 * THIS SOFTWARE IS PROVIDED BY NXP "AS IS" AND ANY EXPRESSED OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL NXP OR ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "Cpu.h"

#if defined(USING_OS_FREERTOS)
/* FreeRTOS kernel includes. */
#include "FreeRTOS.h"
#include "task.h"
#endif /* defined(USING_OS_FREERTOS) */

#include "osif.h"

#include "config.h"

#if ST_TLS_APP
#include "tlsTask.h"
#define mainLoopTask tlsMainLoopTask
#elif ST_BENCH_W_HSM
#include "hsmBenchTask.h"
#define mainLoopTask hsmBenchMainLoopTask
#elif ST_BENCH_WOLFSSL
#include "wolfSSLBenchTask.h"
#define mainLoopTask wolfSSLBenchMainLoopTask
#else
#warning "No available tasks!"
#endif /* ST_TLS_APP */
#ifndef mainLoopTask
#error "Please define \"mainLoopTask\"!"
#endif

volatile int exit_code = 0;

#if ST_BENCH_WOLFSSL
int customRandSeed(uint8_t* output, uint32_t sz);

/* custom random seed function -- by h1994st */
int customRandSeed(uint8_t* output, uint32_t sz) {
	uint32_t i;
	srand(OSIF_GetMilliseconds());
	for (i = 0; i < sz; i++) {
		output[i] = rand() % 256;
	}
	return 0;
}
#endif

int main(void) {

	/*** Processor Expert internal initialization. DON'T REMOVE THIS CODE!!! ***/
#ifdef PEX_RTOS_INIT
	PEX_RTOS_INIT(); /* Initialization of the selected RTOS. Macro is defined by the RTOS component. */
#endif
	/*** End of Processor Expert internal initialization.                    ***/

	/* Write your code here */
	status_t ret = STATUS_ERROR;

	/* Initialize and configure clocks */
	ret = CLOCK_SYS_Init(g_clockManConfigsArr,
			(uint8_t) CLOCK_MANAGER_CONFIG_CNT, g_clockManCallbacksArr,
			(uint8_t) CLOCK_MANAGER_CALLBACK_CNT);
	DEV_ASSERT(STATUS_SUCCESS == ret);
	ret = CLOCK_SYS_UpdateConfiguration(0U, CLOCK_MANAGER_POLICY_AGREEMENT);
	DEV_ASSERT(STATUS_SUCCESS == ret);

	/* Initialize pins */
	ret = PINS_DRV_Init(NUM_OF_CONFIGURED_PINS, g_pin_mux_InitConfigArr);
	DEV_ASSERT(STATUS_SUCCESS == ret);

	/* Initialize LINFLEXD peripheral for UART echo to console */
	LINFLEXD_UART_DRV_Init(INST_LINFLEXD_UART1, &linflexd_uart1_State,
			&linflexd_uart1_InitConfig0);

	/* Initialize FreeRTOS */
	BaseType_t taskRet = xTaskCreate(mainLoopTask, "mainloop", 256U, NULL, 1,
			NULL);
	/* Start the tasks and timer running. */
	DEV_ASSERT(taskRet == pdPASS);
	vTaskStartScheduler();

	/* If all is well, the scheduler will now be running, and the following
	 line will never be reached.  If the following line does execute, then
	 there was insufficient FreeRTOS heap memory available for the idle and/or
	 timer tasks to be created.  See the memory management section on the
	 FreeRTOS web site for more details. */
	for (;;) {
	}

	/*** Don't write any code pass this line, or it will be deleted during code generation. ***/
  /*** RTOS startup code. Macro PEX_RTOS_START is defined by the RTOS component. DON'T MODIFY THIS CODE!!! ***/
  #ifdef PEX_RTOS_START
    PEX_RTOS_START();                  /* Startup of the selected RTOS. Macro is defined by the RTOS component. */
  #endif
  /*** End of RTOS startup code.  ***/
  /*** Processor Expert end of main routine. DON'T MODIFY THIS CODE!!! ***/
  for(;;) {
    if(exit_code != 0) {
      break;
    }
  }
  return exit_code;
  /*** Processor Expert end of main routine. DON'T WRITE CODE BELOW!!! ***/
} /*** End of main routine. DO NOT MODIFY THIS TEXT!!! ***/

/* END main */
/*!
 ** @}
 */
/*
 ** ###################################################################
 **
 **     This file was created by Processor Expert 10.1 [05.21]
 **     for the NXP C55 series of microcontrollers.
 **
 ** ###################################################################
 */

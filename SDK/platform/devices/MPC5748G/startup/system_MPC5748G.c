/*
** ###################################################################
**     Processor:           MPC5748G
**
**     Abstract:
**         Provides a system configuration function and a global variable that
**         contains the system frequency. It configures the device and initializes
**         the oscillator (PLL) that is part of the microcontroller device.
**
**     Copyright (c) 2015 Freescale Semiconductor, Inc.
**     Copyright 2016-2019 NXP
**     All rights reserved.
**
**     THIS SOFTWARE IS PROVIDED BY NXP "AS IS" AND ANY EXPRESSED OR
**     IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
**     OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
**     IN NO EVENT SHALL NXP OR ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
**     INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
**     (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
**     SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
**     HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
**     STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
**     IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
**     THE POSSIBILITY OF SUCH DAMAGE.
**
**
** ###################################################################
*/

/**
 * @page misra_violations MISRA-C:2012 violations
 *
 * @section [global]
 * Violates MISRA 2012 Advisory Rule 11.4, Conversion between a pointer and
 * integer type.
 * The cast is required to initialize a pointer with an unsigned int define,
 * representing a memory-mapped address.
 *
 * @section [global]
 * Violates MISRA 2012 Advisory Rule 8.7, External could be made static.
 * Function is defined for usage by application code.
 *
 * @section [global]
 * Violates MISRA 2012 Required Rule 11.1, Conversions shall not be performed
 * between a pointer to a function and any other type.
 * This is required in order to write the prefix of the interrupt vector table.
 *
 * @section [global]
 * Violates MISRA 2012 Advisory Rule 8.9, An object should be defined at block
 * scope if its identifier only appears in a single function.
 * All variables with this problem are defined in the linker files.
 *
 * @section [global]
 * Violates MISRA 2012 Required Rule 11.6, Cast from pointer to unsigned int.
 * The cast is required to initialize a pointer with an unsigned int define,
 * representing a memory-mapped address.
 *
 * @section [global]
 * Violates MISRA 2012 Advisory Rule 8.7, External could be made static.
 * Function is defined for usage by application code.
 *
 * @section [global]
 * Violates MISRA 2012 Advisory Rule 2.5, local macro not referenced.
 * KEY_VALUE1 and KEY_VALUE2 are used for enabling cores.
 *
 */

/*!
 * @file MPC5748G
 * @version 1.0
 * @date 2017-02-14
 * @brief Device specific configuration file for MPC5748G (implementation file)
 *
 * Provides a system configuration function and a global variable that contains
 * the system frequency. It configures the device and initializes the oscillator
 * (PLL) that is part of the microcontroller device.
 */

#include <stdint.h>
#include "system_MPC5748G.h"


/* ----------------------------------------------------------------------------
   -- Core clock
   ---------------------------------------------------------------------------- */

uint32_t SystemCoreClock = DEFAULT_SYSTEM_CLOCK;

/*FUNCTION**********************************************************************
 *
 * Function Name : SystemInit
 * Description   : Typically this function enables cores,
 * initializes interrupt controller for current core and grants access
 * to peripherals for DMA. SystemInit is called from startup_device file.
 *
 * Implements    : SystemInit_Activity
 *END**************************************************************************/
void SystemInit(void) 
{
  /**************************************************************************/
                    /* ENABLE CORES */
  /**************************************************************************/

#define KEY_VALUE1 0x5AF0u
#define KEY_VALUE2 0xA50Fu

#if defined(DEBUG_SECONDARY_CORES)
    #define START_SECONDARY_CORES
#endif

#if defined(START_SECONDARY_CORES)
    uint32_t mctl = MC_ME->MCTL;
#if defined(TURN_ON_CPU1)
    uint32_t cpu1_bootAddr = 0U;
    #if defined(__cpu1_boot_addr__)
        cpu1_bootAddr = __cpu1_boot_addr__;
    #else
        #if defined(START_FROM_FLASH)
            cpu1_bootAddr = 0x011d0000U;
        #else
            cpu1_bootAddr = 0x40040000U;
        #endif /* defined(START_FROM_FLASH) */
    #endif /* defined(__cpu1_boot_addr__) */
    /* enable core 1 in all modes */
    MC_ME->CCTL2 = 0x00FEU;
    /* Set Start address for core 1: Will reset and start */
    MC_ME->CADDR2 = cpu1_bootAddr | 0x1U;
#endif /* defined(TURN_ON_CPU1) */
#if defined(TURN_ON_CPU2)
    uint32_t cpu2_bootAddr = 0U;
    #if defined(__cpu2_boot_addr__)
        cpu2_bootAddr = __cpu2_boot_addr__;
    #else
        #if defined(START_FROM_FLASH)
            cpu2_bootAddr = 0x013a0000U;
        #else
            cpu2_bootAddr = 0x40080000U;
        #endif /* defined(START_FROM_FLASH) */
    #endif /* defined(__cpu2_boot_addr__) */
    /* enable core 2 in all modes */
    MC_ME->CCTL3 = 0x00FEU;
    /* Set Start address for core 2: Will reset and start */
    MC_ME->CADDR3 = cpu2_bootAddr | 0x1U;
#endif /* defined(TURN_ON_CPU2) */
    MC_ME->MCTL = (mctl & 0xffff0000ul) | KEY_VALUE1;
    MC_ME->MCTL =  mctl; /* key value 2 always from MCTL */
#endif /* defined(START_SECONDARY_CORES) */

/**************************************************************************/
                      /* FPU ENABLE*/
/**************************************************************************/
#ifdef ENABLE_FPU
//TODO: Support FPU
#endif /* ENABLE_FPU */
#if INIT_INTERRUPT_CONTROLLER
    /* initialize interrupt controller for current core */
    uint8_t coreId = GET_CORE_ID();
    switch (coreId) 
    {
        case 0U:
            /* Software vector mode used for core 0 */
            INTC->BCR  &= ~(INTC_BCR_HVEN0_MASK);
            /* Lower core 0's INTC current priority to 0 */
            INTC->CPR0 = 0U;
            break;
        case 1U:
            /* Software vector mode used for core 1 */
            INTC->BCR  &= ~(INTC_BCR_HVEN1_MASK);
            /* Lower core 1's INTC current priority to 0 */
            INTC->CPR1 = 0U;
            break;
        case 2U:
            /* Software vector mode used for core 2 */
            INTC->BCR  &= ~(INTC_BCR_HVEN2_MASK);
            /* Lower core 2's INTC current priority to 1 */
            INTC->CPR2 = 0U;
            break;
        default:
            /* invalid core number */
            DEV_ASSERT(false);
            break;
    }
    /* Initialize core's spr IVPR register*/
    MTSPR(63,(uint32_t)&VTABLE);
#endif

/**************************************************************************/
            /* GRANT ACCESS TO PERIPHERALS FOR DMA MASTER */
/**************************************************************************/
#if ENABLE_DMA_ACCESS_TO_PERIPH
    /* DMA trusted for read/writes in supervisor & user modes on peripheral bridge A */
    AIPS_A->MPRA |= AIPS_MPRA_MTW4_MASK;
    AIPS_A->MPRA |= AIPS_MPRA_MTR4_MASK;
    AIPS_A->MPRA |= AIPS_MPRA_MPL4_MASK;
    /* DMA trusted for read/writes in supervisor & user modes on peripheral bridge B */
    AIPS_B->MPRA |= AIPS_MPRA_MPL4_MASK;
    AIPS_B->MPRA |= AIPS_MPRA_MTW4_MASK;
    AIPS_B->MPRA |= AIPS_MPRA_MTR4_MASK;
#endif
}

/*FUNCTION**********************************************************************
 *
 * Function Name : SystemCoreClockUpdate
 * Description   : This function must be called whenever the core clock is changed
 * during program execution. It evaluates the clock register settings and calculates
 * the current core clock.
 *
 * Implements    : SystemCoreClockUpdate_Activity
 *END**************************************************************************/
void SystemCoreClockUpdate(void) 
{
    uint32_t SYSClock = 0U;
    uint32_t PLLClock = 0U;
    uint32_t prediv, dividerBitsValue, multiBitsValue;
    uint32_t divider = 0u;
    uint32_t multi = 0u;
    bool validSystemClockSource = true;
    /* Get current system clock switch status */
    switch ((MC_ME->GS & MC_ME_GS_S_SYSCLK_MASK) >> MC_ME_GS_S_SYSCLK_SHIFT) 
    {
        case 0x0:
            /* 16MHz int. RC osc */
            SYSClock = CPU_INT_FAST_CLK_HZ;
            break;
        case 0x1:
            /* Fast external oscillator */
            SYSClock = CPU_EXT_FAST_CLK_HZ;
            break;
        case 0x2:
            /* PLL PHI_0 */
            if (((MC_CGM->AC5_SC & MC_CGM_AC5_SC_SELCTL_MASK) >> MC_CGM_AC5_SC_SELCTL_SHIFT) == 0u) 
            {
                PLLClock = CPU_INT_FAST_CLK_HZ;
            }
            else 
            {
                PLLClock = CPU_EXT_FAST_CLK_HZ;
            }
            /* Check output enable for PHI_0*/
            if (((PLLDIG->PLLSR & PLLDIG_PLLSR_ENPHI_MASK) >> PLLDIG_PLLSR_ENPHI_SHIFT) != 0u) 
            {
                validSystemClockSource = true;
            }
            else
            {
                validSystemClockSource = false;
                break;
            }
            /* Calculate pre-Divider */
            prediv = ((PLLDIG->PLLDV & PLLDIG_PLLDV_PREDIV_MASK) >> PLLDIG_PLLDV_PREDIV_SHIFT);
            if (prediv == 0x0u) 
            {
                prediv += 0x1u;
            }
            else if (prediv > 6u) 
            {
                validSystemClockSource = false;
                break;
            }
            else 
            {
                /*do nothing*/
            }
            /* Calculate Out Divider */
            dividerBitsValue = ((PLLDIG->PLLDV & PLLDIG_PLLDV_RFDPHI_MASK) >> PLLDIG_PLLDV_RFDPHI_SHIFT);
            if (dividerBitsValue < 0x7u) 
            {
                divider =(uint32_t)0x2 << dividerBitsValue;
                if (divider > 32u) 
                {
                    divider = 32;
                }
            }
            else 
            {
                validSystemClockSource = false;
            }
            /* Calculate Loop multiplication factor divider */
            multiBitsValue = ((PLLDIG->PLLDV & PLLDIG_PLLDV_MFD_MASK) >> PLLDIG_PLLDV_MFD_SHIFT);
            if ((multiBitsValue > 0xAu) && (multiBitsValue < 0x96u)) 
            {
                multi = multiBitsValue;
            }
            else 
            {
                validSystemClockSource = false;
            }
            /* Calculate System clock */
            if (validSystemClockSource) 
            {
                if (divider != 0u)
                {
                    SYSClock = PLLClock * multi /(prediv*divider);
                }
                else
                {
                /* Do nothing*/
                }
            }
            break;
        default:
            validSystemClockSource = false;
            break;
    }

    if (validSystemClockSource == true)
    {
        SystemCoreClock = SYSClock;
    }
}

/*FUNCTION**********************************************************************
 *
 * Function Name : SystemSoftwareReset
 * Description   : This function is used to initiate a 'functional' reset event
 * to the microcontroller. The reset module will do a state machine from
 * PHASE1->PHASE2->PHASE3->IDLE.
 *
 * Implements    : SystemSoftwareReset_Activity
 *END**************************************************************************/
void SystemSoftwareReset(void)
{
    MC_ME->MCTL = FEATURE_MC_ME_KEY;
    MC_ME->MCTL = MC_ME_MCTL_TARGET_MODE(0x00) | FEATURE_MC_ME_KEY_INV;
}

/*******************************************************************************
 * EOF
 ******************************************************************************/

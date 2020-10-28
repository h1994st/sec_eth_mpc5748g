/*
*   Copyright 2018 NXP.
*/

#ifndef CPU_DEFINES_H
#define CPU_DEFINES_H

#if (defined(CPU_MPC5747C) || defined(CPU_MPC5748C) || defined(CPU_MPC5746G) || defined(CPU_MPC5747G) || defined(CPU_MPC5748G) || \
     defined(CPU_MPC5744B) || defined(CPU_MPC5745B) || defined(CPU_MPC5746B) || defined(CPU_MPC5744C) || defined(CPU_MPC5745C)  || defined(CPU_MPC5746C) || \
     defined(CPU_MPC5741P) || defined(CPU_MPC5742P) || defined(CPU_MPC5743P) || defined(CPU_MPC5744P) || \
     defined(CPU_S32R264)  || defined(CPU_S32R274)  || defined(CPU_S32R372) || \
     defined(CPU_MPC5743R) || defined(CPU_MPC5745R) || defined(CPU_MPC5746R))
    #define INTC_CPR_ADDR_BASE                      0xFC040010
    #define INTC_IACKR_PRC_ADDR_BASE                0xFC040020
    #define INTC_EOIR_PRC_ADDR_BASE                 0xFC040030
    #define INTC_IACKR_INTVEC_BITWIDTH_NUM_BASE     10
    #define INTC_OFFSET_NUM                            2
#elif defined(CPU_MPC5775E) || defined(CPU_MPC5775B) || defined(CPU_MPC5777C)
    #define INTC_CPR_ADDR_BASE                      0xFFF48008
    #define INTC_IACKR_PRC_ADDR_BASE                0xFFF48010
    #define INTC_EOIR_PRC_ADDR_BASE                 0xFFF48018
    #define INTC_IACKR_INTVEC_BITWIDTH_NUM_BASE     10
    #define INTC_OFFSET_NUM                            2
#else
    #error not define platform
#endif

    #define INTC_OFFSET(coreId)                        (coreId << INTC_OFFSET_NUM)
    #define INTC_CPR_ADDR(coreId)                      INTC_CPR_ADDR_BASE + INTC_OFFSET((coreId))
    #define INTC_IACKR_PRC_ADDR(coreId)                INTC_IACKR_PRC_ADDR_BASE + INTC_OFFSET((coreId))
    #define INTC_EOIR_PRC_ADDR(coreId)                 INTC_EOIR_PRC_ADDR_BASE + INTC_OFFSET((coreId))
    #define INTC_IACKR_INTVEC_BITWIDTH_NUM             INTC_IACKR_INTVEC_BITWIDTH_NUM_BASE

#endif/* CPU_DEFINES_H */

#ifndef _HQ_INTERFACES_TX_H_
#define _HQ_INTERFACES_TX_H_

#include "interfaces.h"

#if INTERFACE_TYPE == INTERFACE_TYPE_MODEL
#include "../interfaces/model.h"
using tx_interface = HQ::MODEL::TX;
#else
#error "Unrecognized interface type!"
#endif /* INTERFACE_TYPE */

#endif /* _HQ_INTERFACES_TX_H_ */

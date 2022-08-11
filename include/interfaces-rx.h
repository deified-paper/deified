#ifndef _HQ_INTERFACES_RX_H_
#define _HQ_INTERFACES_RX_H_

#include "interfaces.h"

#if INTERFACE_TYPE == INTERFACE_TYPE_MODEL
#include "../interfaces/model.h"
using rx_interface = HQ::MODEL::RX;
#else
#error "Unrecognized interface type!"
#endif /* INTERFACE_TYPE */

#endif /* _HQ_INTERFACES_RX_H_ */

#include <iostream>

#include <unistd.h>
#include <pthread.h>

#include "config.h"
#include "interfaces-rx.h"
#include "interfaces-tx.h"
#include "messages.h"

const unsigned NUM_THREADS = 8;
const unsigned MSG_SEND = 100;

rx_interface interface_rx;
tx_interface interface_tx;

void *thread(void *arg) {
    for (unsigned i = 0; i < MSG_SEND; ++i)
        interface_tx.send_msg1(HQ_MSG_INVALIDATE, 0);

    std::cout << gettid() << ": Sent " << MSG_SEND << " messages!\n";
    return nullptr;
}

int main(int argc, char **argv) {
    pthread_t threads[NUM_THREADS];

    auto fd = tx_interface::create();
    if (fd < 0) {
        std::cerr << "Failed to create interface!" << std::endl;
        return -1;
    }

#if INTERFACE_TYPE != INTERFACE_TYPE_PAGES &&                                  \
    INTERFACE_TYPE != INTERFACE_TYPE_ZERO
    if (!interface_rx.open(fd)) {
        std::cerr << "Failed to open RX interface!" << std::endl;
        return -1;
    }
#endif /* INTERFACE_TYPE */

    if (!interface_tx.open(fd)) {
        std::cerr << "Failed to open TX interface!" << std::endl;
        return -1;
    }

    #pragma nounroll
    for (unsigned i = 0; i < NUM_THREADS; ++i)
        pthread_create(&threads[i], nullptr, &thread, nullptr);
    #pragma nounroll
    for (unsigned i = 0; i < NUM_THREADS; ++i)
        pthread_join(threads[i], nullptr);

    size_t received = 0;
    auto it = interface_rx.begin(), it_end = interface_rx.get_msgs();
    if (!it_end) {
        std::cerr << "Failed to receive message!" << std::endl;
        return -1;
    }

    // Iterator may do work; cannot take difference
    while (it != it_end) {
        ++it;
        ++received;
    }

    std::cout << "Received " << received << " messages!\n";
    if (received != NUM_THREADS * MSG_SEND)
        std::cout << "Expected " << NUM_THREADS * MSG_SEND << " messages!\n";

    return 0;
}

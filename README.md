# DeiFIed: Protecting Web Browsers with Data-Flow Integrity

Users frequently use web browsers to interact with untrusted remote content, either directly via Apple Safari, Google Chrome, Microsoft Edge, and the like, or indirectly through embedded frameworks like Electron and NodeJS. However, web browsers are mostly written in unsafe languages like C and C++, which are vulnerable to memory-safety bugs. Indeed, past statistics from Google Chrome and Microsoft have shown that ~70% of security vulnerabilities in their products involve such bugs. In response, numerous security mitigations have been deployed, including no-execute memory, stack canaries, and even control-flow integrity. Nevertheless, recent exploits have shown that browsers are still vulnerable to non-control-data attacks, which can alter program execution without changing control-flow.

In this paper, we leverage emerging work on hardware-based instruction monitoring to develop DeiFIed, an efficient and scalable data-flow integrity (DFI) design that can protect any application from these attacks, including large and complex web browsers. Using automated compiler instrumentation, we rewrite protected programs to send software-defined events to an external verifier process whenever security-sensitive data are accessed. For performance reasons, we perform policy checking asynchronously, synchronizing program and verifier only at system calls. Compared to prior DFI work, DeiFIed maximizes context sensitivity by protecting runtime data integrity without imprecise and unscalable pointer alias analysis. Our implementation and evaluation on the open-source Google Chromium web browser demonstrates the correctness, effectiveness, and performance of our approach.

# Multi Threaded Proxy Server with and without Cache

This project is implemented using C, with HTTP parsing referred from the Proxy Server.

## Index
- [Project Theory](#project-theory)
- [How to Run](#how-to-run)
- [Demo](#demo)
- [Contributing](#contributing)

---

## Project Theory

### Introduction

This project implements a multi-threaded proxy server with and without a cache. The proxy server acts as an intermediary between the client and the server, handling multiple client requests concurrently while optionally caching responses to improve performance.

### Basic Working Flow of the Proxy Server

1. A client sends an HTTP request to the proxy server.
2. The proxy checks the cache to see if the response is already stored.
3. If the response is found in the cache, it is returned to the client.
4. If the response is not in the cache, the proxy fetches it from the actual server and stores it in the cache for future use.

### How did we implement Multi-threading?

- Used **semaphore** instead of condition variables, and the `pthread_join()` and `pthread_exit()` functions.
- `pthread_join()` requires us to pass the thread ID of the thread to wait for. Semaphore's `sem_wait()` and `sem_post()` don't need any parameters, making semaphores a better option for handling concurrency.

### Motivation/Need of Project

This project is designed to:
- Understand the flow of requests from a local computer to the server.
- Handle multiple client requests simultaneously.
- Implement proper locking procedures for concurrency.
- Explore the concept of cache and how it is used by browsers to improve response time.

#### Proxy Server's Role:
- **Speeds up the process** and reduces traffic on the server side.
- Can **restrict access to certain websites**.
- **Hides the client IP** from the server, providing anonymity.
- Can be extended to **encrypt requests** for added security.

### OS Components Used
- **Threading**
- **Locks**
- **Semaphore**
- **Cache (LRU algorithm)**

### Limitations
- If a URL opens multiple clients, the cache will store each client’s response separately, leading to incomplete responses when retrieved.
- Fixed cache element size, so large websites may not fit into the cache.

### How this project can be extended?
- Implement **multiprocessing** to speed up the process with parallelism.
- Extend the code to decide which types of websites should be allowed.
- Support additional HTTP methods like **POST**.

### Notes
- The code is well-commented. If you have any questions, you can refer to the comments in the code.

---

## How to Run

To run the proxy server, follow these steps:

1. Clone the repository:
   ```bash
   $ git clone https://github.com/Lovepreet-Singh-LPSK/MultiThreadedProxyServerClient.git
   $ cd MultiThreadedProxyServerClient
   $ make all
   $ ./proxy <port_no>



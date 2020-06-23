/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "../wrappers/common.h"
#include "../wrappers/client-agent/start_agent.h"
#include "../client-agent/agentd.h"

extern void send_msg_on_startup(void);
extern bool agent_handshake_to_server();
extern int _s_verify_counter;


void __wrap__mwarn(const char * file, int line, const char * func, const char *msg, ...) {
   return;
}

void __wrap__mdebug1(const char * file, int line, const char * func, const char *msg, ...) {
   return;
}

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...) {
    return;
}

void __wrap__minfo(const char * file, int line, const char * func, const char *msg, ...) {
    return;
}
void __wrap_w_rotate_log(int compress, int keep_log_days, int new_day, int rotate_json, int daily_rotations) {
    return;
}

#ifndef TEST_WINAGENT
int __wrap_close(int fd) {
    check_expected(fd);
    return 0;
}
#endif

int __wrap_OS_ConnectUDP(u_int16_t _port, const char *_ip, int ipv6) {
    return mock();
}
int __wrap_OS_ConnectTCP(u_int16_t _port, const char *_ip, int ipv6) {
    return mock();
}

int __wrap_OS_SetRecvTimeout(int socket, long seconds, long useconds) {
    return mock();
}

void __wrap_resolveHostname(char **hostname, int attempts) {
    if (strcmp(*hostname, "VALID_HOSTNAME/") == 0) {    
        free(*hostname);
        os_strdup("VALID_HOSTNAME/127.0.0.3", *hostname);
    } else {
        free(*hostname);
        os_strdup("INVALID_HOSTNAME/", *hostname);
    }
}

int __wrap_getDefine_Int(const char *high_name, const char *low_name, int min, int max) {
    return mock();
}

int __wrap_send_msg(const char *msg, ssize_t msg_length) {
    check_expected(msg);
    return 0;
}

#ifndef TEST_WINAGENT
ssize_t __wrap_recv(int __fd, void *__buf, size_t __n, int __flags) {
    char* rcv = (char*)mock_ptr_type(char *);
    int len = strlen(rcv);
    snprintf(__buf, len+1, "%s", rcv);
    return len;
}
#endif

int __wrap_OS_RecvSecureTCP(int sock, char * ret,uint32_t size) {
    char* rcv = (char*)mock_ptr_type(char *);
    int len = strlen(rcv);
    snprintf(ret, len+1, "%s", rcv);
    return len;
}

int __wrap_fseek(FILE *__stream, long __off, int __whence) {
    return 0;
}
int __wrap_fprintf(FILE *__restrict__ __stream, const char *__restrict__ __format, ...) {
    return 0;
}
int __wrap_fflush(FILE *__stream) {
    return 0;
}

int __wrap_ReadSecMSG(keystore *keys, char *buffer, char *cleartext, int id, unsigned int buffer_size, size_t *final_size, const char *srcip, char **output) {
    check_expected(buffer);
    *output = (char*)mock_ptr_type(char *);
    return (int)mock();
}
  
/* Aux */
/* ACK encrypted with id=001, Name=agent0 and key=6958b43cb096e036f872d65d6a4dc01b3c828f64a204c04 */
char SERVER_ENC_ACK[] = {0x23,0x41,0x45,0x53,0x3a,0x4c,0x63,0x7a,0xef,0x9e,0x16,0xcc,0x94,0xf8,0xfc,0x5e,0x81,0xc9,0x80,0x24,0xd3,0x61,0xc6,0xb7,0x9b,0xdf,0xb1,0xfe,0xf5,0xa0,0x31,0xa7,0xba,0x92,0x74,0x3b,0xda,0x0c,0x70,0xed,0x39,0x8f,0xb7,0xda,0xe2,0xe0,0xcb,0x9c,0x86,0x87,0x39,0xaa,0x7b,0xb9,0x5a,0xb3,0xa5,0x81,0xea,0x78,0x15,0xa9,0xfd,0x8b,0x14,0xfb,0x6b,0xcb,0x08,0x04,0x0d,0x77,0xf6,0xd7,0xbc,0x29,0xeb,0x06,0x84,0x07,0x14,0x55,0xaf,0x0c,0x37,0x00};
char SERVER_NULL_ACK[] = {0x00};
char SERVER_WRONG_ACK[] = {0x01,0x02,0x03,0x00};

void add_server_config(char* address, int protocol) {
    os_realloc(agt->server, sizeof(agent_server) * (agt->rip_id + 2), agt->server);
    os_strdup(address, agt->server[agt->rip_id].rip);
    agt->server[agt->rip_id].port = 0;
    agt->server[agt->rip_id].protocol = 0;
    memset(agt->server + agt->rip_id + 1, 0, sizeof(agent_server));
    agt->server[agt->rip_id].protocol = protocol;
    agt->rip_id++; 
}

void keys_init(keystore *keys) {
    /* Initialize hashes */
    keys->keyhash_id = OSHash_Create();
    keys->keyhash_ip = OSHash_Create();
    keys->keyhash_sock = OSHash_Create();

    if (!(keys->keyhash_id && keys->keyhash_ip && keys->keyhash_sock)) {
        merror_exit(MEM_ERROR, errno, strerror(errno));
    }

    /* Initialize structure */
    os_calloc(1, sizeof(keyentry*), keys->keyentries);
    keys->keysize = 0;
    keys->id_counter = 0;
    keys->flags.rehash_keys = 0;
    keys->flags.save_removed = 0;

    /* Add additional entry for sender == keysize */
    os_calloc(1, sizeof(keyentry), keys->keyentries[keys->keysize]);
    w_mutex_init(&keys->keyentries[keys->keysize]->mutex, NULL);    
}

/* setup/teardown */
static int setup_test(void **state) {
    agt = (agent *)calloc(1, sizeof(agent));    
    /* Default conf */
    agt->server = NULL;
    agt->lip = NULL;
    agt->rip_id = 0;
    agt->execdq = 0;
    agt->cfgadq = -1;
    agt->profile = NULL;
    agt->buffer = 1;
    agt->buflength = 5000;
    agt->events_persec = 500;
    agt->flags.auto_restart = 1;
    agt->crypto_method = W_METH_AES;
    /* Connected sock */
    agt->sock=-1;
    /* Server */
    add_server_config("127.0.0.1", IPPROTO_UDP);
    add_server_config("127.0.0.2", IPPROTO_TCP);
    add_server_config("VALID_HOSTNAME/", IPPROTO_UDP);
    add_server_config("INVALID_HOSTNAME/", IPPROTO_UDP);
    
    /* Keys */
    keys_init(&keys);    
    OS_AddKey(&keys, "001", "agent0", "any", "6958b43cb096e036f872d65d6a4dc01b3c828f64a204c04");
    os_set_agent_crypto_method(&keys,agt->crypto_method);

    _s_verify_counter = 0;

    return 0;
}

static int teardown_test(void **state) {
    os_free(agt->server);
    os_free(agt);
    return 0;
}

/* tests */
/* connect_server */
static void test_connect_server(void **state) { 
    bool connected = false; 
    /* Connect to first server (UDP)*/ 
    will_return(__wrap_getDefine_Int, 5);
    will_return(__wrap_OS_ConnectUDP, 11);
    will_return(__wrap_OS_SetRecvTimeout, 0);
    connected = connect_server(0);
    assert_int_equal(agt->rip_id, 0);
    assert_int_equal(agt->sock, 11);    
    assert_true(connected);

    /* Connect to second server (TCP), previous connection must be closed*/
    will_return(__wrap_getDefine_Int, 5);
    will_return(__wrap_OS_ConnectTCP, 12);
    will_return(__wrap_OS_SetRecvTimeout, 0);
    #ifndef TEST_WINAGENT
    expect_value(__wrap_close, fd, 11);
    #else
    expect_value(wrap_closesocket, fd, 11);
    #endif
    connected = connect_server(1);  
    assert_int_equal(agt->rip_id, 1);  
    assert_int_equal(agt->sock, 12);
    assert_true(connected);

    /* Connect to third server (UDP), valid host name*/
    will_return(__wrap_getDefine_Int, 5);
    will_return(__wrap_OS_ConnectUDP, 13);
    will_return(__wrap_OS_SetRecvTimeout, 0);
    #ifndef TEST_WINAGENT
    expect_value(__wrap_close, fd, 12);
    #else
    expect_value(wrap_closesocket, fd, 12);
    #endif
    connected = connect_server(2); 
    assert_int_equal(agt->rip_id, 2);  
    assert_int_equal(agt->sock, 13);
    assert_true(connected);

    /* Connect to fourth server (UDP), invalid host name*/
    will_return(__wrap_getDefine_Int, 5);
    #ifndef TEST_WINAGENT
    expect_value(__wrap_close, fd, 13);
    #else
    expect_value(wrap_closesocket, fd, 13);
    #endif
    connected = connect_server(3);     
    assert_false(connected);

    /* Connect to first server (UDP), simulate connection error*/
    will_return(__wrap_getDefine_Int, 5);
    will_return(__wrap_OS_ConnectUDP, -1);    
    connected = connect_server(0); 
    assert_false(connected);
            
    return;
}

static void test_connect_server_timeout_error(void **state) { 
    bool connected = false; 
    /* Connect to first server (UDP)*/ 
    will_return(__wrap_getDefine_Int, 5);
    will_return(__wrap_OS_ConnectUDP, 11);
    will_return(__wrap_OS_SetRecvTimeout, -1);
    errno = ENOPROTOOPT;
    connected = connect_server(0);
    assert_int_equal(agt->rip_id, 0);
    assert_int_equal(agt->sock, 11);    
    assert_true(connected);
}

static void test_connect_server_timeout_error_2(void **state) { 
    bool connected = false; 
    /* Connect to first server (UDP)*/ 
    will_return(__wrap_getDefine_Int, 5);
    will_return(__wrap_OS_ConnectUDP, 11);
    will_return(__wrap_OS_SetRecvTimeout, -1);
    errno = EFAULT;
    connected = connect_server(0);   
    assert_false(connected);
}

/* agent_handshake_to_server */
static void test_agent_handshake_to_server(void **state) {
    bool handshaked = false;

    /* Handshake with first server (UDP) */
    will_return(__wrap_getDefine_Int, 5);
    will_return(__wrap_OS_ConnectUDP, 21);
    will_return(__wrap_OS_SetRecvTimeout, 0);
    #ifndef TEST_WINAGENT
    will_return(__wrap_recv, SERVER_ENC_ACK);
    #else 
    will_return(wrap_recv, SERVER_ENC_ACK);
    #endif
    expect_string(__wrap_send_msg, msg, "#!-agent startup ");    
    expect_string(__wrap_ReadSecMSG, buffer, SERVER_ENC_ACK);
    will_return(__wrap_ReadSecMSG, "#!-agent ack ");
    will_return(__wrap_ReadSecMSG, KS_VALID);

    agt->rip_id = 0;
    handshaked = agent_handshake_to_server();
    assert_true(handshaked);

    /* Handshake with second server (TCP) */
    will_return(__wrap_getDefine_Int, 5);
    will_return(__wrap_OS_ConnectTCP, 22);
    will_return(__wrap_OS_SetRecvTimeout, 0);
    #ifndef TEST_WINAGENT
    expect_value(__wrap_close, fd, 21);
    #else
    expect_value(wrap_closesocket, fd, 21);
    #endif
    will_return(__wrap_OS_RecvSecureTCP, SERVER_ENC_ACK);
    expect_string(__wrap_send_msg, msg, "#!-agent startup ");   
    expect_string(__wrap_ReadSecMSG, buffer, SERVER_ENC_ACK);
    will_return(__wrap_ReadSecMSG, "#!-agent ack ");
    will_return(__wrap_ReadSecMSG, KS_VALID);

    agt->rip_id = 1;
    handshaked = agent_handshake_to_server();
    assert_true(handshaked);

    /* Handshake with connection error */
    will_return(__wrap_getDefine_Int, 5);
    will_return(__wrap_OS_ConnectUDP, -1);
    #ifndef TEST_WINAGENT
    expect_value(__wrap_close, fd, 22);
    #else
    expect_value(wrap_closesocket, fd, 22);
    #endif     
    agt->rip_id = 0;
    handshaked = agent_handshake_to_server();
    assert_false(handshaked);

    /* Handshake with reception error */
    will_return(__wrap_getDefine_Int, 5);
    will_return(__wrap_OS_ConnectUDP, 23);
    will_return(__wrap_OS_SetRecvTimeout, 0);
    #ifndef TEST_WINAGENT
    will_return(__wrap_recv, SERVER_NULL_ACK);
    #else 
    will_return(wrap_recv, SERVER_NULL_ACK);
    #endif
    expect_string(__wrap_send_msg, msg, "#!-agent startup ");
    agt->rip_id = 0;
    handshaked = agent_handshake_to_server();
    assert_false(handshaked);

    /* Handshake with decode error */
    will_return(__wrap_getDefine_Int, 5);
    will_return(__wrap_OS_ConnectUDP, 23);
    will_return(__wrap_OS_SetRecvTimeout, 0);
    #ifndef TEST_WINAGENT
    expect_value(__wrap_close, fd, 23);
    will_return(__wrap_recv, SERVER_WRONG_ACK);
    #else
    expect_value(wrap_closesocket, fd, 23);
    will_return(wrap_recv, SERVER_WRONG_ACK);
    #endif
    expect_string(__wrap_send_msg, msg, "#!-agent startup "); 
    expect_string(__wrap_ReadSecMSG, buffer, SERVER_WRONG_ACK);
    will_return(__wrap_ReadSecMSG, SERVER_WRONG_ACK);
    will_return(__wrap_ReadSecMSG, KS_CORRUPT);    
    agt->rip_id = 0;
    handshaked = agent_handshake_to_server();
    assert_false(handshaked);

    return;
}

/* agent_start_up_to_server */
static void test_send_msg_on_startup(void **state) {
    expect_string(__wrap_send_msg, msg, "1:ossec:ossec: Agent started: 'agent0->any'.");
    send_msg_on_startup(); 
    return;                            
}

int main(void) {
    const struct CMUnitTest tests[] = {              
        cmocka_unit_test_setup_teardown(test_connect_server, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_agent_handshake_to_server, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_send_msg_on_startup, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_connect_server_timeout_error, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_connect_server_timeout_error_2, setup_test, teardown_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
#pragma once

#include <zmq.hpp>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <thread>
#include <atomic>
#include <regex>

#include "ecdsa.h"

class HeartbeatMonitorClient {
private:
    const char* c_status_a[5] = {"OFF", "OK", "WARNING", "ERROR", "CRITICAL"};

    zmq::context_t *m_context;
    zmq::socket_t *m_status_socket;
    zmq::socket_t *m_control_socket;
    char *m_status_address;
    char *m_control_address;
    std::thread *m_thread_p;
    ecc_base *m_ecc_p;
    
    static bool m_on;
    static std::atomic<bool> m_active;
    
    uint64_t timestampNow();
    std::string statusMsg();
    int checkSignature(char *inmsg, char *&msg);
    void setSockOpt(zmq::socket_t *socket, int linger, int timeout);
    void listenControl();
public:
    HeartbeatMonitorClient(std::string status_address, std::string control_address, ecc_base *ecc_p, int linger = 0, int timeout = 500):
                                        m_context(new zmq::context_t(1)),
                                        m_status_socket(new zmq::socket_t(*m_context, ZMQ_REP)),
                                        m_control_socket(new zmq::socket_t(*m_context, ZMQ_REP)),
                                        m_thread_p(nullptr),
                                        m_ecc_p(ecc_p)
    {
        m_status_address = (char *) malloc(status_address.length());
        strcpy(m_status_address, status_address.c_str());
        m_control_address = (char *) malloc(control_address.length());
        strcpy(m_control_address, control_address.c_str());
        setSockOpt(m_status_socket, linger, timeout);
        zmq_bind(*m_control_socket, m_control_address);
        zmq_bind(*m_status_socket, m_status_address);
    }
    
    ~HeartbeatMonitorClient() {
        m_on = false;
        if (m_thread_p)
            m_thread_p->join();
        zmq_unbind(*m_control_socket, m_control_address);
        zmq_unbind(*m_status_socket, m_status_address);
        zmq_close(*m_status_socket);
        zmq_close(*m_control_socket);
        zmq_term(m_context);
    }
    
    void run();
};

bool HeartbeatMonitorClient::m_on = true;
std::atomic<bool> HeartbeatMonitorClient::m_active = true;

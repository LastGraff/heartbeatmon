#pragma once

#include <zmq.hpp>
#include <string>
#include <iostream>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <thread>

#include "ecdsa.h"

class HeartbeatMonitorServer {
private:
    zmq::context_t *m_monitor_context;
    zmq::context_t *m_control_context;
    zmq::socket_t *m_monitor_socket;
    zmq::socket_t *m_control_socket;
    char *m_monitor_address;
    char *m_control_address;
    int m_freq;
    int m_stop_prob;
    ecc_base *m_ecc_p;
    
    const char* c_ping  = "ping";
    
    static bool m_on;
    
    void setSockOpt(zmq::socket_t *socket, int linger, int timeout);
    bool sendPing();
    bool sendStop();
    std::string addSignature(std::string msg);
    std::string timestampReq();
public:
    HeartbeatMonitorServer(std::string monitor_address, std::string control_address, ecc_base *ecc_p, int freq = 1000, int stop_prob = 20, int linger = 0, int timeout = 500): 
                                    m_monitor_context(new zmq::context_t(1)),
                                    m_control_context(new zmq::context_t(1)),
                                    m_monitor_socket(new zmq::socket_t(*m_monitor_context, ZMQ_REQ)),
                                    m_control_socket(new zmq::socket_t(*m_control_context, ZMQ_REQ)),
                                    m_freq(freq),
                                    m_stop_prob(stop_prob),
                                    m_ecc_p(ecc_p) 
    {
        m_monitor_address = (char *) malloc(monitor_address.length());
        strcpy(m_monitor_address, monitor_address.c_str());
        m_control_address = (char *) malloc(control_address.length());
        strcpy(m_control_address, control_address.c_str());
        setSockOpt(m_monitor_socket, linger, timeout);
        setSockOpt(m_control_socket, linger, timeout);
        zmq_connect(*m_monitor_socket, m_monitor_address);
        zmq_connect(*m_control_socket, m_control_address);
    }
    
    ~HeartbeatMonitorServer() {
        m_on = false;
        zmq_disconnect(*m_monitor_socket, m_monitor_address);
        zmq_disconnect(*m_control_socket, m_control_address);

        zmq_close(*m_monitor_socket);
        zmq_close(*m_control_socket);
        zmq_term(m_monitor_context);
        zmq_term(m_control_context);
    }
    
    void run();
};

bool HeartbeatMonitorServer::m_on = true;

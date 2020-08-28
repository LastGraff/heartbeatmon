#include "server.h"

void HeartbeatMonitorServer::setSockOpt(zmq::socket_t *socket, int linger, int timeout) {
    zmq_setsockopt(*socket, ZMQ_LINGER, &linger, sizeof(linger));
    zmq_setsockopt(*socket, ZMQ_RCVTIMEO, &timeout, sizeof(timeout));
    zmq_setsockopt(*socket, ZMQ_SNDTIMEO, &timeout, sizeof(timeout));
    zmq_setsockopt(*socket, ZMQ_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
}
    
bool HeartbeatMonitorServer::sendPing() {
    int rc;
    char buf[256] = {};
    
    rc = zmq_send(*m_monitor_socket, c_ping, strlen(c_ping), 0);
    if (rc == -1) {
        zmq_recv (*m_monitor_socket, buf, 256, 1);
        return false;
    }
    rc = zmq_recv (*m_monitor_socket, buf, 256, 0);
    if (rc == -1)
        return false;
    else
        return true;
}

std::string HeartbeatMonitorServer::addSignature(std::string msg) {
    m_ecc_p->sign((uint8_t *)msg.c_str(), msg.length());
    return std::to_string(msg.length()) + " " +
           std::to_string(m_ecc_p->get_signature_len()) + " " +
           msg + m_ecc_p->get_signature();
}

bool HeartbeatMonitorServer::sendStop() {
    int rc;
    char buf[256] = {};
    std::string stop = "stop" + timestampReq();
    stop = addSignature(stop);
    rc = zmq_send(*m_control_socket, stop.c_str(), stop.length(), 0);
    if (rc == -1) {
        zmq_recv (*m_control_socket, buf, 256, 1);
        return false;
    }
    else {
        rc = zmq_recv (*m_control_socket, buf, 256, 0);
        return true;
    }
}

std::string HeartbeatMonitorServer::timestampReq() {
    uint64_t timestamp = std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    return std::to_string(timestamp);
}

void HeartbeatMonitorServer::run() {
    int rc;
    while (m_on) {
        
        if (!sendPing()) {
            std::cout << "Ping was lost" << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(m_freq));
            continue;
        }
          
        char buf[256] = {};
        
        std::string monitor_msg = "areYouAlive" + timestampReq();
        monitor_msg = addSignature(monitor_msg);
        rc = zmq_send(*m_monitor_socket, monitor_msg.c_str(), monitor_msg.length(), 0);
        if (rc == -1) {
            std::cout << "Request was not send." << std::endl;
            zmq_recv (*m_monitor_socket, buf, 256, 1);
            std::this_thread::sleep_for(std::chrono::milliseconds(m_freq));
            continue;
        }
        
        rc = zmq_recv (*m_monitor_socket, buf, 256, 0);
        if (rc == -1) {
            std::cout<<"Reply was not received."<< std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(m_freq));
            continue;
        }
        std::cout << buf << std::endl;
        
        //send stop at random iteration
        if (rand() % 100 < m_stop_prob) {
            if (sendStop())
                std::cout << "Stop message was send" << std::endl;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(m_freq));
    }

}

int main(int argc, char **argv) {
    ecc_base ecc;
    std::string private_key_path = (argc == 2)? argv[1]: "./ecprivkey.pem";

    if (ecc.load_privkey(private_key_path) == -1) {
        std::cout << "Could not read the private key." << std::endl;
        return -1;
    }
    const std::string monitor_address = "tcp://127.0.0.1:12277";//"tcp://172.17.0.2:12277";
    const std::string control_address = "tcp://127.0.0.1:12278";//"tcp://172.17.0.2:12278";

    HeartbeatMonitorServer server ( monitor_address, control_address, &ecc, 1000, 30); //send requests every 1000ms, sending stop probability is 30%
    server.run();
    return 0;
}

#include "client.h"


uint64_t HeartbeatMonitorClient::timestampNow() {
    return std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
}


std::string HeartbeatMonitorClient::statusMsg() {
    int status_idx1, status_idx2;
    boost::property_tree::ptree rep_tree;
    if (m_active) {
        status_idx1 = rand() % 5;
        status_idx2 = rand() % 5;
    }
    else {
        status_idx1 = 0;
        status_idx2 = 0;
        m_active = true;
    }
    rep_tree.put("AliveAt", timestampNow());
    rep_tree.put("Status.subsystem1", c_status_a[status_idx1]);
    rep_tree.put("Status.subsystem2", c_status_a[status_idx2]);
    std::stringstream rep_ss;
    boost::property_tree::write_json(rep_ss, rep_tree);
    return rep_ss.str();
}

void HeartbeatMonitorClient::setSockOpt(zmq::socket_t *socket, int linger, int timeout) {
    zmq_setsockopt(*socket, ZMQ_LINGER, &linger, sizeof(linger));
    zmq_setsockopt(*socket, ZMQ_SNDTIMEO, &timeout, sizeof(timeout));
}

int HeartbeatMonitorClient::checkSignature(char *inmsg, char *&msg) {
    char buf[5] = {0};
    char *msg_len_end_p;
    msg_len_end_p = strchr(inmsg, ' ');
    if (msg_len_end_p == NULL)
        return -1;
    strncpy(&buf[0], inmsg, (size_t)(msg_len_end_p - inmsg));
    int msg_len = atoi(buf);
    
    msg = (char *) malloc(msg_len + 1);
    char *sig_len_end_p;
    sig_len_end_p = strchr(msg_len_end_p + 1, ' ');
    if (sig_len_end_p == NULL)
        return -1;
    strncpy( &buf[0], msg_len_end_p + 1, (size_t)(sig_len_end_p - msg_len_end_p - 1));
    int sig_len = atoi(buf);
   
    strncpy(msg, sig_len_end_p + 1, msg_len);
    msg[msg_len] = 0;
    
    int a= m_ecc_p->verify((uint8_t *)sig_len_end_p + 1 + msg_len, sig_len, (uint8_t *)sig_len_end_p + 1, msg_len) + 1;
    return a;
    
}

void HeartbeatMonitorClient::listenControl() {
    while (m_on)  {
        char buf [256] = {};
        std::string rep_str;
        char *msg;
        zmq_recv (*m_control_socket, buf, 256, 0);
        
        if (checkSignature(buf, msg) == 1 && std::regex_match(msg, std::regex("(stop)[0-9]*")))
            m_active = false;
        zmq_send(*m_control_socket, "ok", 2, 0);
    }
}

void HeartbeatMonitorClient::run() {
    m_thread_p = new std::thread(&HeartbeatMonitorClient::listenControl, this);
    int rc;  
    const char ping_req[] = "ping";
    while (m_on) {
        char buf [256] = {};
        std::string rep_str;
        rc = zmq_recv (*m_status_socket, buf, 256, 0);
        char *msg;
        if (strcmp(buf, ping_req) == 0)
            rep_str = "pong";
        else 
            if (checkSignature(buf, msg) == 1 && std::regex_match(msg, std::regex("(areYouAlive)[0-9]*")))               
                rep_str = statusMsg();
            else 
                rep_str = "wrong request";
            
        rc = zmq_send(*m_status_socket, rep_str.c_str(),rep_str.length(), 0);
    }
}

int main(int argc, char **argv) {
    ecc_base ecc;
    if (ecc.load_pubkey("./ecpubkey.pem") == -1) {
        std::cout << "Could not read the public key." << std::endl;
        return -1;
    }
    
    const std::string monitor_address = "tcp://*:12277";
    const std::string control_address = "tcp://*:12278";
    
    HeartbeatMonitorClient client ( monitor_address, control_address, &ecc);
    client.run();
    return 0;
}

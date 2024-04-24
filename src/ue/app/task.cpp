//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//
#include <iostream>
#include <ue/types.hpp>
#include "task.hpp"
#include "cmd_handler.hpp"
#include <lib/nas/utils.hpp>
#include <ue/nas/task.hpp>
#include <ue/rls/task.hpp>
#include <ue/tun/tun.hpp>
#include <utils/common.hpp>
#include <utils/constants.hpp>

#include <sstream>
#include <vector>
#include <string>
#include <stdexcept>

std::vector<int> findAllMaintainIndices() {
    std::vector<int> maintainIndices;
    for (size_t i = 0; i < NtsTask::apSelection.additionalInfo.size(); ++i) {
        if (NtsTask::apSelection.additionalInfo[i] == "Maintain") {
            maintainIndices.push_back(i);
        }
    }
    return maintainIndices;
}

std::vector<unsigned char> ip_to_bytes(const std::string& ip_address) 
{
    std::vector<unsigned char> bytes;

    // Create a string stream to tokenize the IP address string
    std::istringstream iss(ip_address);
    std::string octet;

    // Tokenize the IP address string by '.' delimiter and convert each octet to its numeric value
    while (std::getline(iss, octet, '.')) {
        // Convert the octet string to an integer and store it as a byte
        unsigned char byte = static_cast<unsigned char>(std::stoi(octet));
        bytes.push_back(byte);
    }
  return bytes;
}

// Function to execute a command
int execute_command(const std::string& command) {
    return system(command.c_str());
}

// Function to build the command
std::string build_command(const std::string& base_cmd,  const std::string& target_network, const std::string interface) {
    return base_cmd +" via " + target_network + " dev "+ interface ;
}

// Function to add  route
int route(const std::string& target_network, const std::string interface) {
    std::string cmd = build_command("ip route add default", target_network, interface);
    return execute_command(cmd);
}
// Function to delete route

int delete_route(const std::string& target_network, const std::string interface){
    std::string cmd = build_command("ip route del default ",target_network, interface);
    return execute_command(cmd);
}

static constexpr const int SWITCH_OFF_TIMER_ID = 1;
static constexpr const int SWITCH_OFF_DELAY = 500;

namespace nr::ue
{

UeAppTask::UeAppTask(TaskBase *base) : m_base{base}
{
    m_logger = m_base->logBase->makeUniqueLogger(m_base->config->getLoggerPrefix() + "app");
}

void UeAppTask::onStart()
{
    std::string ip_address = m_base->config->staticIP;
    try {
	bytes = ip_to_bytes(ip_address);
	// bytes will now contain {10, 0, 4, 14}
    } catch (const std::invalid_argument& e) {
	std::cerr << "Error: " << e.what() << std::endl;
}

}

void UeAppTask::onQuit()
{
    for (auto &tunTask : m_tunTasks)
    {
        if (tunTask != nullptr)
        {
            tunTask->quit();
            delete tunTask;
            tunTask = nullptr;
        }
    }
}

void UeAppTask::onLoop()
{
    auto msg = take();
    if (!msg){	
	if (NtsTask::establishConnection == true)
    	{
	PduSession wifiSession(1);
        wifiSession.psState = EPsState::ACTIVE;
        wifiSession.uplinkPending = true;
        wifiSession.sessionType = nas::EPduSessionType::IPV4;
        //std::vector<unsigned char> bytes = {0b00001010, 0b00000000, 0b00000001, 0b00001110};
        OctetString address(std::move(bytes)); // Use std::move to cast bytes to an rvalue reference
        nas::IEPduAddress pduAddress(wifiSession.sessionType, std::move(address)); // Wrap OctetString in IEPduA>
        wifiSession.pduAddress = std::move(pduAddress); // Assign IEPduAddress to pduAddress member of session
	std::vector<int> maintainIndices = findAllMaintainIndices();
        if (!maintainIndices.empty() )
        {
             std::cout << "Indices where 'Maintain' occurs:" << std::endl;
             for (int maintainIndex : maintainIndices) {
             std::cout << maintainIndex <<std::endl;
             if (maintainIndex > 0) {
             NtsTask::apSelection.additionalInfo[maintainIndex] = "Establish"; // Assign empty string to the element
             int status = system("ip route del default");
             if (status == 0) {
                     m_logger->info("Deleted previous connection");
                     }
             }
             }
        }
	if ( NtsTask::apSelection.additionalInfo[0] == "Establish")
	{
        int status = route(NtsTask::apSelection.ipv4address[0], m_base->config->interface);
	std::cout<<m_base->config->interface<<std::endl;
	std::cout<<status;
        if (status == 0)
        {
                m_logger->info("Building Connection.");
        }
        setupTunInterface(&wifiSession); // Pass the address of session to setupTunInterface
	NtsTask::connectionEstablished = true;
	NtsTask::apSelection.additionalInfo[0] =  std::move("Maintain");
	}
	else if (NtsTask::apSelection.additionalInfo[0] == "Maintain" && NtsTask::counter < 10)
	{
		return;
	}
	else if (NtsTask::counter > SWITCH_OFF_DELAY)
	{
	    int status = delete_route(NtsTask::apSelection.ipv4address[0], m_base->config->interface);
            if (status == 0)
            {
                m_logger->info("Time out removing Connection.");
            }
	    if (m_tunTasks[wifiSession.psi] != nullptr)
            {
                m_tunTasks[wifiSession.psi]->quit();
                delete m_tunTasks[wifiSession.psi];
                m_tunTasks[wifiSession.psi] = nullptr;
            }
	    NtsTask::counter = 0;
	    NtsTask::establishConnection = false;
	    NtsTask::connectionEstablished = false;
	}
        else
        {
            int status = system("ip route del default");
            if (status == 0)
            {
                m_logger->info("Removing Connection.");
            }
            if (m_tunTasks[wifiSession.psi] != nullptr)
            {
                m_tunTasks[wifiSession.psi]->quit();
                delete m_tunTasks[wifiSession.psi];
                m_tunTasks[wifiSession.psi] = nullptr;
            }
           //NtsTask::apSelection.additionalInfo[0] = "";
        }

	}
    return;
    }
    switch (msg->msgType)
    {
    case NtsMessageType::UE_TUN_TO_APP: {
        auto &w = dynamic_cast<NmUeTunToApp &>(*msg);
        switch (w.present)
        {
        case NmUeTunToApp::DATA_PDU_DELIVERY: {
            auto m = std::make_unique<NmUeAppToNas>(NmUeAppToNas::UPLINK_DATA_DELIVERY);
            m->psi = w.psi;
            m->data = std::move(w.data);
            m_base->nasTask->push(std::move(m));
            break;
        }
        case NmUeTunToApp::TUN_ERROR: {
            m_logger->err("TUN failure [%s]", w.error.c_str());
            break;
        }
        }
        break;
    }
    case NtsMessageType::UE_NAS_TO_APP: {
        auto &w = dynamic_cast<NmUeNasToApp &>(*msg);
        switch (w.present)
        {
        case NmUeNasToApp::PERFORM_SWITCH_OFF: {
            setTimer(SWITCH_OFF_TIMER_ID, SWITCH_OFF_DELAY);
            break;
        }
        case NmUeNasToApp::DOWNLINK_DATA_DELIVERY: {
            auto *tunTask = m_tunTasks[w.psi];
            if (tunTask)
            {
                auto m = std::make_unique<NmAppToTun>(NmAppToTun::DATA_PDU_DELIVERY);
                m->psi = w.psi;
                m->data = std::move(w.data);
                tunTask->push(std::move(m));
            }
            break;
        }
        }
        break;
    }
    case NtsMessageType::UE_STATUS_UPDATE: {
        receiveStatusUpdate(dynamic_cast<NmUeStatusUpdate &>(*msg));
        break;
    }
    case NtsMessageType::UE_CLI_COMMAND: {
        auto &w = dynamic_cast<NmUeCliCommand &>(*msg);
        UeCmdHandler handler{m_base};
        handler.handleCmd(w);
        break;
    }
    case NtsMessageType::TIMER_EXPIRED: {
        auto &w = dynamic_cast<NmTimerExpired &>(*msg);
        if (w.timerId == SWITCH_OFF_TIMER_ID)
        {
            m_logger->info("UE device is switching off");
            m_base->ueController->performSwitchOff(m_base->ue);
        }
        break;
    }
    default:
        m_logger->unhandledNts(*msg);
        break;
    }
}

void UeAppTask::receiveStatusUpdate(NmUeStatusUpdate &msg)
{
    if (msg.what == NmUeStatusUpdate::SESSION_ESTABLISHMENT)
    {
        auto *session = msg.pduSession;

        setupTunInterface(session);
        return;
    }

    if (msg.what == NmUeStatusUpdate::SESSION_RELEASE)
    {
        if (m_tunTasks[msg.psi] != nullptr)
        {
            m_tunTasks[msg.psi]->quit();
            delete m_tunTasks[msg.psi];
            m_tunTasks[msg.psi] = nullptr;
        }

        return;
    }

    if (msg.what == NmUeStatusUpdate::CM_STATE)
    {
        m_cmState = msg.cmState;
        return;
    }
}

void UeAppTask::setupTunInterface(const PduSession *pduSession)
{
    if (!utils::IsRoot())
    {
        m_logger->err("TUN interface could not be setup. Permission denied. Please run the UE with 'sudo'");
        return;
    }

    if (!pduSession->pduAddress.has_value())
    {
        m_logger->err("Connection could not setup. PDU address is missing.");
        return;
    }

    if (pduSession->pduAddress->sessionType != nas::EPduSessionType::IPV4 ||
        pduSession->sessionType != nas::EPduSessionType::IPV4)
    {
        m_logger->err("Connection could not setup. PDU session type is not supported.");
        return;
    }

    int psi = pduSession->psi;
    if (psi == 0 || psi > 15)
    {
        m_logger->err("Connection could not setup. Invalid PSI.");
        return;
    }

    if (m_tunTasks[psi] != nullptr)
    {
        m_logger->err("Connection could not setup. TUN task for specified PSI is non-null.");
        return;
    }

    std::string error{}, allocatedName{};
    std::string requestedName = cons::TunNamePrefix;
    if (m_base->config->tunName.has_value())
        requestedName = *m_base->config->tunName;
    int fd = tun::TunAllocate(requestedName.c_str(), allocatedName, error);
    if (fd == 0 || error.length() > 0)
    {
        m_logger->err("TUN allocation failure [%s]", error.c_str());
        return;
    }

    std::string ipAddress = utils::OctetStringToIp(pduSession->pduAddress->pduAddressInformation);

    bool r = tun::TunConfigure(allocatedName, ipAddress, cons::TunMtu, m_base->config->configureRouting, error);
    if (!r || error.length() > 0)
    {
        m_logger->err("TUN configuration failure [%s]", error.c_str());
        return;
    }

    auto *task = new TunTask(m_base, psi, fd);
    m_tunTasks[psi] = task;
    task->start();

    m_logger->info("Connection setup for PDU session[%d] is successful, TUN interface[%s, %s] is up.", pduSession->psi,
                   allocatedName.c_str(), ipAddress.c_str());
}

} // namespace nr::ue

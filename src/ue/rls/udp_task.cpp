//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "udp_task.hpp"
#include <iostream>
#include <cstdint>
#include <cstring>
#include <set>
#include <cstdlib>
#include <cmath>
#include <ue/app/task.hpp>
#include <ue/nts.hpp>
#include <utils/common.hpp>
#include <utils/constants.hpp>

static constexpr const int BUFFER_SIZE = 16384;
static constexpr const int LOOP_PERIOD = 1000;
static constexpr const int RECEIVE_TIMEOUT = 200;
static constexpr const int HEARTBEAT_THRESHOLD = 2000; // (LOOP_PERIOD + RECEIVE_TIMEOUT)'dan büyük olmalı

bool NtsTask::connectionEstablished = false;
bool NtsTask::establishConnection = false;
std::string NtsTask::state = "";
int NtsTask::counter = 0;
namespace nr::ue
{

RlsUdpTask::RlsUdpTask(TaskBase *base, RlsSharedContext *shCtx, const std::vector<std::string> &searchSpace, std::vector<Vector3> simPos, const int velocity, const bool wifi)
    : m_server{}, m_ctlTask{}, m_shCtx{shCtx}, m_searchSpace{}, m_cells{}, m_cellIdToSti{}, m_lastLoop{},m_simPos{simPos},
      m_cellIdCounter{},m_velocity{velocity}, m_wifi{wifi}
{
    m_logger = base->logBase->makeUniqueLogger(base->config->getLoggerPrefix() + "rls-udp");

    m_server = new udp::UdpServer();
    for (auto &ip : searchSpace)
        m_searchSpace.emplace_back(ip, cons::RadioLinkPort);
}

void RlsUdpTask::onStart()
{
   m_simPosIndex = 0;
   velocity_in_time = speedTimeCalculation(m_simPos, m_velocity);
}

void RlsUdpTask::onLoop()
{
    auto current = utils::CurrentTimeMillis();
    if (current - m_lastLoop > velocity_in_time)
    {
        m_lastLoop = current;
        // Increment the index to move to the next position in m_simPos
        m_simPosIndex = (m_simPosIndex + 1) % m_simPos.size();
        // Pass the corresponding Vector3 to heartbeatCycle
        heartbeatCycle(current, m_simPos[m_simPosIndex]);
        //heartbeatCycle(current, m_simPos);
    }

    uint8_t buffer[BUFFER_SIZE];
    InetAddress peerAddress;

    int size = m_server->Receive(buffer, BUFFER_SIZE, RECEIVE_TIMEOUT, peerAddress);
    if (size > 0)
    {
        auto rlsMsg = rls::DecodeRlsMessage(OctetView{buffer, static_cast<size_t>(size)});
        if (rlsMsg == nullptr)
            m_logger->err("Unable to decode RLS message");
        else
            receiveRlsPdu(peerAddress, std::move(rlsMsg));
    }
    else
    {
	NtsTask::counter++;
    }
}

void RlsUdpTask::onQuit()
{
    delete m_server;
}

void RlsUdpTask::sendRlsPdu(const InetAddress &addr, const rls::RlsMessage &msg)
{
    OctetString stream;
    rls::EncodeRlsMessage(msg, stream);

    m_server->Send(addr, stream.data(), static_cast<size_t>(stream.length()));
}

void RlsUdpTask::send(int cellId, const rls::RlsMessage &msg)
{
    if (m_cellIdToSti.count(cellId))
    {
        auto sti = m_cellIdToSti[cellId];
        sendRlsPdu(m_cells[sti].address, msg);
    }
}

void RlsUdpTask::receiveRlsPdu(const InetAddress &addr, std::unique_ptr<rls::RlsMessage> &&msg)
{
    if (msg->msgType == rls::EMessageType::HEARTBEAT_ACK)
    {
        if (!m_cells.count(msg->sti))
        {
            m_cells[msg->sti].cellId = ++m_cellIdCounter;
            m_cellIdToSti[m_cells[msg->sti].cellId] = msg->sti;
        }

        int oldDbm = INT32_MIN;
        if (m_cells.count(msg->sti))
            oldDbm = m_cells[msg->sti].dbm;

        m_cells[msg->sti].address = addr;
        m_cells[msg->sti].lastSeen = utils::CurrentTimeMillis();

        int newDbm = ((const rls::RlsHeartBeatAck &)*msg).dbm;
        m_cells[msg->sti].dbm = newDbm;
	if (m_wifi)
        {
            if (newDbm > -120 && NtsTask::establishConnection == false)
            {
                NtsTask::state = std::move("Establish");
                NtsTask::establishConnection = true;
            }
            else if (newDbm > -120 && NtsTask::establishConnection == true && NtsTask::connectionEstablished == true)
            {
                state = std::move("Maintain");
            }
	    else if (newDbm < -120)
	    {
		state = std::move("Release");
		NtsTask::connectionEstablished = false;
	    }
        }
	NtsTask::counter = 0;
        if (oldDbm != newDbm)
           {onSignalChangeOrLost(m_cells[msg->sti].cellId);}
	return;
    }

    if (!m_cells.count(msg->sti))
    {
        // if no HB-ACK received yet, and the message is not HB-ACK, then ignore the message
        state = std::move("Release");
        NtsTask::connectionEstablished = false;
        return;
    }

    auto w = std::make_unique<NmUeRlsToRls>(NmUeRlsToRls::RECEIVE_RLS_MESSAGE);
    w->cellId = m_cells[msg->sti].cellId;
    w->msg = std::move(msg);
    m_ctlTask->push(std::move(w));
}

void RlsUdpTask::onSignalChangeOrLost(int cellId)
{
    int dbm = INT32_MIN;
    if (m_cellIdToSti.count(cellId))
    {
        auto sti = m_cellIdToSti[cellId];
        dbm = m_cells[sti].dbm;
    }

    auto w = std::make_unique<NmUeRlsToRls>(NmUeRlsToRls::SIGNAL_CHANGED);
    w->cellId = cellId;
    w->dbm = dbm;
    m_ctlTask->push(std::move(w));

}

void RlsUdpTask::heartbeatCycle(uint64_t time, const Vector3 &simPos)
{
    std::set<std::pair<uint64_t, int>> toRemove;

    for (auto &cell : m_cells)
    {
        auto delta = time - cell.second.lastSeen;
        if (delta >  RECEIVE_TIMEOUT + velocity_in_time + velocity_in_time + 100)
            toRemove.insert({cell.first, cell.second.cellId});
    }

    for (auto cell : toRemove)
    {
        m_cells.erase(cell.first);
        m_cellIdToSti.erase(cell.second);
    }

    for (auto cell : toRemove)
        onSignalChangeOrLost(cell.second);

    for (auto &addr : m_searchSpace)
    {
        rls::RlsHeartBeat msg{m_shCtx->sti};
        msg.simPos = simPos;
        sendRlsPdu(addr, msg);
    }
}

void RlsUdpTask::initialize(NtsTask *ctlTask)
{
    m_ctlTask = ctlTask;
}

int RlsUdpTask::speedTimeCalculation(const std::vector<Vector3> simPos, int velocity)
{
    std::vector<double> x_values, y_values, z_values;
    for (const auto& vector : simPos) {
        x_values.push_back(vector.x);
        y_values.push_back(vector.y);
        z_values.push_back(vector.z);
    }

    size_t size = x_values.size();
    int lastIndex = size - 1;
    int deltaX = x_values[lastIndex] - x_values[0];
    int deltaY = y_values[lastIndex] - y_values[0];
    int deltaZ = z_values[lastIndex] - z_values[0];

    // Compute squared distances separately and then take the square root
    double squaredDistance = deltaX * deltaX + deltaY * deltaY + deltaZ * deltaZ;
    double distance = std::sqrt(squaredDistance);

    double time;
    if (distance == 0) {
        distance = 1;
        time = 0;
    } else {
        double time_in_sec = distance / velocity;
        std::cout << "time in second: " << time_in_sec << std::endl;
        time = time_in_sec * 1000; // convert into millisecond
        std::cout << "time in millisecond: " << time << std::endl;
    }

    return time;

}

} // namespace nr::ue

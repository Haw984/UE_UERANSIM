//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "rls_pdu.hpp"

#include <utils/constants.hpp>
#include "asn/ngap/ASN_NGAP_QosFlowSetupRequestItem.h"
#include <iostream>

void printSecurityCapability(const nas::IEUeSecurityCapability& cap) {
    std::cout << "IEUeSecurityCapability values:" << std::endl;
    std::cout << "b_5G_EA0: " << cap.b_5G_EA0 << std::endl;
    std::cout << "b_128_5G_EA1: " << cap.b_128_5G_EA1 << std::endl;
    std::cout << "b_128_5G_EA2: " << cap.b_128_5G_EA2 << std::endl;
    std::cout << "b_128_5G_EA3: " << cap.b_128_5G_EA3 << std::endl;
    std::cout << "b_5G_EA4: " << cap.b_5G_EA4 << std::endl;
    std::cout << "b_5G_EA5: " << cap.b_5G_EA5 << std::endl;
    std::cout << "b_5G_EA6: " << cap.b_5G_EA6 << std::endl;
    std::cout << "b_5G_EA7: " << cap.b_5G_EA7 << std::endl;
    std::cout << "b_5G_IA0: " << cap.b_5G_IA0 << std::endl;
    std::cout << "b_128_5G_IA1: " << cap.b_128_5G_IA1 << std::endl;
    std::cout << "b_128_5G_IA2: " << cap.b_128_5G_IA2 << std::endl;
    std::cout << "b_128_5G_IA3: " << cap.b_128_5G_IA3 << std::endl;
    std::cout << "b_5G_IA4: " << cap.b_5G_IA4 << std::endl;
    std::cout << "b_5G_IA5: " << cap.b_5G_IA5 << std::endl;
    std::cout << "b_5G_IA6: " << cap.b_5G_IA6 << std::endl;
    std::cout << "b_5G_IA7: " << cap.b_5G_IA7 << std::endl;
    std::cout << "b_EEA0: " << cap.b_EEA0 << std::endl;
    std::cout << "b_128_EEA1: " << cap.b_128_EEA1 << std::endl;
    std::cout << "b_128_EEA2: " << cap.b_128_EEA2 << std::endl;
    std::cout << "b_128_EEA3: " << cap.b_128_EEA3 << std::endl;
    std::cout << "b_EEA4: " << cap.b_EEA4 << std::endl;
    std::cout << "b_EEA5: " << cap.b_EEA5 << std::endl;
    std::cout << "b_EEA6: " << cap.b_EEA6 << std::endl;
    std::cout << "b_EEA7: " << cap.b_EEA7 << std::endl;
    std::cout << "b_EIA0: " << cap.b_EIA0 << std::endl;
    std::cout << "b_128_EIA1: " << cap.b_128_EIA1 << std::endl;
    std::cout << "b_128_EIA2: " << cap.b_128_EIA2 << std::endl;
    std::cout << "b_128_EIA3: " << cap.b_128_EIA3 << std::endl;
    std::cout << "b_EIA4: " << cap.b_EIA4 << std::endl;
    std::cout << "b_EIA5: " << cap.b_EIA5 << std::endl;
    std::cout << "b_EIA6: " << cap.b_EIA6 << std::endl;
    std::cout << "b_EIA7: " << cap.b_EIA7 << std::endl;
}

namespace rls
{

void EncodeRlsMessage(const RlsMessage &msg, OctetString &stream)
{
    stream.appendOctet(0x03); // (Just for old RLS compatibility)

    stream.appendOctet(cons::Major);
    stream.appendOctet(cons::Minor);
    stream.appendOctet(cons::Patch);
    stream.appendOctet(static_cast<uint8_t>(msg.msgType));
    stream.appendOctet8(msg.sti);
    if (msg.msgType == EMessageType::HEARTBEAT)
    {
        auto &m = (const RlsHeartBeat &)msg;
        stream.appendOctet4(m.simPos.x);
        stream.appendOctet4(m.simPos.y);
        stream.appendOctet4(m.simPos.z);
    }
    else if (msg.msgType == EMessageType::HEARTBEAT_ACK)
    {
        auto &m = (const RlsHeartBeatAck &)msg;
        stream.appendOctet4(m.dbm);
    }
    else if (msg.msgType == EMessageType::PDU_TRANSMISSION)
    {
        auto &m = (const RlsPduTransmission &)msg;
        stream.appendOctet(static_cast<uint8_t>(m.pduType));
        stream.appendOctet4(m.pduId);
        stream.appendOctet4(m.payload);
        stream.appendOctet4(m.pdu.length());
        stream.append(m.pdu);
    }
    else if (msg.msgType == EMessageType::PDU_TRANSMISSION_ACK)
    {
        auto &m = (const RlsPduTransmissionAck &)msg;
        stream.appendOctet4(static_cast<uint32_t>(m.pduIds.size()));
        for (auto pduId : m.pduIds)
            stream.appendOctet4(pduId);
    }
    //Urwah
    else if (msg.msgType == EMessageType::RELEASE_SESSION)
    {
        auto &m = (const RlsTerminateSession &)msg;
        std::cout<<"m.pduId EMessageType::RELEASE_SESSION: "<<m.pduId<<std::endl;
        stream.appendOctet4(m.pduId);
        stream.appendOctet4(m.psi);

    }
    else if (msg.msgType == EMessageType::SESSION_TRANSMISSION)
    {
        std::cout<<"msg.msgType == EMessageType::SESSION_TRANSMISSION"<<std::endl;
        auto &m = (const RlsSessionTransmission &)msg;
        //stream.appendOctet(static_cast<uint8_t>(m.pduType));
        if (m.m_pduSession > 0)
        {
            std::cout<<"Khali nai ha bhai"<<std::endl;
        }
        else
        {
            std::cout<<"Khali ha"<<std::endl;
        }
        stream.appendOctet4(m.pduId);
        stream.appendOctet4(m.payload);
        stream.appendOctet4(m.amfId);
        stream.appendOctet4(m.length_ueCtx);
        stream.append(m.m_ueCtx);
        //serialize(stream, m_pduSession);
        //%%%%%%%%%%%%%%%%%%
        //size_t len = 0;
        auto &qosList = m.m_pduSession->qosFlows->list;
        /*len += sizeof(uint8_t); // Number of QoS Flows
        for (int iQos = 0; iQos < qosList.count; iQos++) {
            len += sizeof(uint8_t); // qosFlowIdentifier
            // Add length calculation for other fields in ASN_NGAP_QosFlowSetupRequestItem if necessary
        }*/
        //stream.appendOctet4(static_cast<uint32_t>(len));
        //@@@@@@@@@@@@@@@
        stream.appendOctet4(static_cast<uint32_t>(m.m_pduSession->ueId)); // Serialize ueId
        stream.appendOctet4(static_cast<uint32_t>(m.m_pduSession->psi));  // Serialize psi

        // Serialize AggregateMaximumBitRate
        stream.appendOctet8(m.m_pduSession->sessionAmbr.dlAmbr); // Serialize dlAmbr
        stream.appendOctet8(m.m_pduSession->sessionAmbr.ulAmbr); // Serialize ulAmbr

        // Serialize boolean as a single byte
        stream.appendOctet(static_cast<uint8_t>(m.m_pduSession->dataForwardingNotPossible));

        // Serialize PduSessionType as a single byte
        stream.appendOctet(static_cast<uint8_t>(m.m_pduSession->sessionType));

        // Serialize GtpTunnel upTunnel
        stream.appendOctet4(m.m_pduSession->upTunnel.teid); // Serialize TEID
        //int64_t address_size = sizeof(m.m_pduSession->upTunnel.address);

        //std::cout<<"Address: "<< address_size<<std::endl;
        stream.appendOctet4(m.m_pduSession->upTunnel.address.length());
        stream.append(m.m_pduSession->upTunnel.address);    // Serialize address
        std::cout<<"res->m_pduSession->upTunnel.teid: "<<m.m_pduSession->upTunnel.teid<<std::endl;
        std::cout << "Size of OctetString object: " << sizeof(m.m_pduSession->upTunnel.address) << " bytes" << std::endl;
        // Assuming m.m_pduSession->upTunnel.address is an OctetString
        for (size_t i = 0; i < sizeof(m.m_pduSession->upTunnel.address); ++i) {
            if (i != 0) {
                std::cout << ".";
            }
            std::cout << static_cast<int>(m.m_pduSession->upTunnel.address.data()[i]);
        }
        std::cout << std::endl;
 
        // Serialize GtpTunnel downTunnel
        stream.appendOctet4(m.m_pduSession->downTunnel.teid); // Serialize TEID
        stream.appendOctet4(m.m_pduSession->downTunnel.address.length());    // Serialize address
        stream.append(m.m_pduSession->downTunnel.address);    // Serialize address
        std::cout<<"res->m_pduSession->downTunnel.teid: "<<m.m_pduSession->downTunnel.teid<<std::endl;
        std::cout << "Size of OctetString object: " << sizeof(m.m_pduSession->downTunnel.address) << " bytes" << std::endl;
        // Assuming m.m_pduSession->upTunnel.address is an OctetString
        for (size_t i = 0; i < sizeof(m.m_pduSession->downTunnel.address); ++i) {
            if (i != 0) {
                std::cout << ".";
            }
            std::cout << static_cast<int>(m.m_pduSession->downTunnel.address.data()[i]);
        }

        std::cout << std::endl;

        std::cout<<"/n GTP Tunnel Address (hex): ";
        for (size_t i = 0; i < sizeof(m.m_pduSession->downTunnel.address); ++i) {
            printf("%02x ", m.m_pduSession->downTunnel.address.data()[i]);
        }
        std::cout << std::endl;
        std::cout<<"res->m_pduSession->qosFlows->list.array[0]->qosFlowIdentifier: "<<qosList.array[0]->qosFlowIdentifier<<std::endl;
        std::cout<<"Encoder: qoslist size"<<qosList.size;
        stream.appendOctet4(static_cast<int>(qosList.count)); // Serialize the number of QoS Flows
        std::cout<<"List: "<<static_cast<int>(qosList.count)<<std::endl;
        for (int iQos = 0; iQos < static_cast<int>(qosList.count); iQos++) {
            stream.appendOctet4(static_cast<int>(qosList.array[iQos]->qosFlowIdentifier)); // Serialize QoS Flow Identifier
            std::cout<<"static_cast<int>(qosList.array[iQos]->qosFlowIdentifier)"<<static_cast<int>(qosList.array[iQos]->qosFlowIdentifier)<<std::endl;
            // Add serialization for other fields in ASN_NGAP_QosFlowSetupRequestItem if necessary
        }
                // ****** Add the UE Security Capability Encoding here ******
        //nas::IEUeSecurityCapability ueSecCap = std::move(m.m_ueSecurityCapability);
        // Initialize `ueSecCap` fields here based on the session or configuration
        // e.g., ueSecCap.b_5G_EA0 = 1, ueSecCap.b_128_5G_EA1 = 0, etc.
        std::cout<< "m.m_ueSecurityCapability.b_5G_EA0: " <<m.m_ueSecurityCapability.b_5G_EA0<<std::endl;
        //printSecurityCapability(m.m_ueSecurityCapability);
        // Encode the UE Security Capability into the stream
        nas::IEUeSecurityCapability::Encode(m.m_ueSecurityCapability, stream);

    }   
}

std::unique_ptr<RlsMessage> DecodeRlsMessage(const OctetView &stream)
{
    auto first = stream.readI(); // (Just for old RLS compatibility)
    if (first != 3)
        return nullptr;

    if (stream.read() != cons::Major)
        return nullptr;
    if (stream.read() != cons::Minor)
        return nullptr;
    if (stream.read() != cons::Patch)
        return nullptr;

    auto msgType = static_cast<EMessageType>(stream.readI());
    uint64_t sti = stream.read8UL();

    if (msgType == EMessageType::HEARTBEAT)
    {
        auto res = std::make_unique<RlsHeartBeat>(sti);
        res->simPos.x = stream.read4I();
        res->simPos.y = stream.read4I();
        res->simPos.z = stream.read4I();
        return res;
    }
    else if (msgType == EMessageType::HEARTBEAT_ACK)
    {
        auto res = std::make_unique<RlsHeartBeatAck>(sti);
        res->dbm = stream.read4I();
        return res;
    }
    else if (msgType == EMessageType::PDU_TRANSMISSION)
    {
        auto res = std::make_unique<RlsPduTransmission>(sti);
        res->pduType = static_cast<EPduType>((uint8_t)stream.read());
        res->pduId = stream.read4UI();
        res->payload = stream.read4UI();
        res->pdu = stream.readOctetString(stream.read4I());
        return res;
    }
    else if (msgType == EMessageType::PDU_TRANSMISSION_ACK)
    {
        auto res = std::make_unique<RlsPduTransmissionAck>(sti);
        auto count = stream.read4UI();
        res->pduIds.reserve(count);
        for (uint32_t i = 0; i < count; i++)
            res->pduIds.push_back(stream.read4UI());
        return res;
    }
    else if (msgType == EMessageType::SESSION_TRANSMISSION)
    {
        auto res = std::make_unique<RlsSessionTransmission>(sti);
        //res->pduType = static_cast<EPduType>((uint8_t)stream.read());
        res->pduId = stream.read4UI();
        res->payload = stream.read4UI();
        res->amfId = stream.read4UI();
        // Step 1: Read the length (first 4 bytes)
        res->length_ueCtx = stream.read4UI();  // This gives you the length of the serialized m_ueCtx

        // Step 2: Store the rest of the data into an OctetString
        res->m_ueCtx = stream.readOctetString(static_cast<size_t>(res->length_ueCtx));  // Cast length to size_t

        int ueId = stream.read4UI();
        int psi = stream.read4UI();
        // Deserialize m_pduSession using the length provided in the stream
        // Read the length of the serialized PDU session
        //size_t len = stream.read4UI();

        // Read and decode m_pduSession
        //std::make_unique<nr::gnb::PduSessionResource> m_pduSession;

        res->m_pduSession = std::make_unique<nr::ue::PduSessionResource>(ueId, psi);

        // Read ueId and psi
        //res->m_pduSession->ueId = stream.read4UI();
        //res->m_pduSession->psi = stream.read4UI();

        // Read AggregateMaximumBitRate
        res->m_pduSession->sessionAmbr.dlAmbr = stream.read8UL();
        res->m_pduSession->sessionAmbr.ulAmbr = stream.read8UL();

        // Read boolean and PduSessionType
        res->m_pduSession->dataForwardingNotPossible = static_cast<bool>(stream.readI());
        res->m_pduSession->sessionType = static_cast<PduSessionType>(stream.readI());

        // Read GtpTunnel upTunnel
        res->m_pduSession->upTunnel.teid = stream.read4UI();
        std::cout<<"res->m_pduSession->upTunnel.teid: "<<res->m_pduSession->upTunnel.teid<<std::endl;
        //int address = sizeof(stream.readI());
        //std::cout<<"Address: "<< address<<std::endl;
        res->m_pduSession->upTunnel.address = stream.readOctetString(stream.read4I());
        std::cout << "Size of OctetString object: " << sizeof(res->m_pduSession->upTunnel.address) << " bytes" << std::endl;
        // Assuming m.m_pduSession->upTunnel.address is an OctetString
        for (size_t i = 0; i < sizeof(res->m_pduSession->upTunnel.address); ++i) {
            if (i != 0) {
                std::cout << ".";
            }
            std::cout << static_cast<int>(res->m_pduSession->upTunnel.address.data()[i]);
        }
        std::cout << std::endl;


        // Read GtpTunnel downTunnel
        res->m_pduSession->downTunnel.teid = stream.read4UI();
        std::cout<<"res->m_pduSession->downTunnel.teid: "<<res->m_pduSession->downTunnel.teid<<std::endl;
        res->m_pduSession->downTunnel.address = stream.readOctetString(stream.read4I());
        std::cout << "Size of OctetString object: " << sizeof(res->m_pduSession->downTunnel.address) << " bytes" << std::endl;
        //std::cout<<"Len: "<<len<<std::endl;
        for (size_t i = 0; i < sizeof(res->m_pduSession->downTunnel.address); ++i) {
            if (i != 0) {
                std::cout << ".";
            }
            std::cout << static_cast<int>(res->m_pduSession->downTunnel.address.data()[i]);
        }
        std::cout<<"GTP Tunnel Address (hex): ";
        for (size_t i = 0; i < sizeof(res->m_pduSession->downTunnel.address); ++i) {
            printf("%02x ", res->m_pduSession->downTunnel.address.data()[i]);
        }
        printf("\n");
        std::cout << std::endl;
        // Read QoS Flows
        int qosFlowCount = stream.read4I();
        std::cout << "List: " << qosFlowCount << std::endl;

        // Allocate space for qosFlows
        asn::Unique<ASN_NGAP_QosFlowSetupRequestList> newQosFlows(asn::New<ASN_NGAP_QosFlowSetupRequestList>());
        res->m_pduSession->qosFlows = std::move(newQosFlows);
        res->m_pduSession->qosFlows->list.array = new ASN_NGAP_QosFlowSetupRequestItem*[qosFlowCount];

        for (int iQos = 0; iQos < qosFlowCount; iQos++) {
            res->m_pduSession->qosFlows->list.array[iQos] = new ASN_NGAP_QosFlowSetupRequestItem();
            res->m_pduSession->qosFlows->list.array[iQos]->qosFlowIdentifier = stream.read4I();
            std::cout<<"res->m_pduSession->qosFlows->list.array[iQos]->qosFlowIdentifier: "<<res->m_pduSession->qosFlows->list.array[iQos]->qosFlowIdentifier<<std::endl;
        }
        res->m_pduSession->qosFlows->list.count = qosFlowCount;
        std::cout<<"res->m_pduSession->qosFlows->list.array[0]->qosFlowIdentifier: "<<res->m_pduSession->qosFlows->list.array[0]->qosFlowIdentifier<<std::endl;

        std::cout<<" Decoding is running@@@"<<std::endl;

        return res;

    }
    else if (msgType == EMessageType::XN_SESSION_TRANSMISSION)
    {
        std::cout<<"~~~~~~~~XN_SESSION_TRANSMISSION~~~~~~~~~~~"<<std::endl;
        auto res = std::make_unique<RlsXnSessionTransmission>(sti);

        int ueId = stream.read4UI();
        int psi = stream.read4UI();


        res->m_pduSession = std::make_unique<nr::ue::PduSessionResource>(ueId, psi);

        // Read AggregateMaximumBitRate
        res->m_pduSession->sessionAmbr.dlAmbr = stream.read8UL();
        res->m_pduSession->sessionAmbr.ulAmbr = stream.read8UL();

        // Read boolean and PduSessionType
        res->m_pduSession->dataForwardingNotPossible = static_cast<bool>(stream.readI());
        res->m_pduSession->sessionType = static_cast<PduSessionType>(stream.readI());

        // Read GtpTunnel upTunnel
        res->m_pduSession->upTunnel.teid = stream.read4UI();
        std::cout<<"res->m_pduSession->upTunnel.teid: "<<res->m_pduSession->upTunnel.teid<<std::endl;
        //int address = sizeof(stream.readI());
        //std::cout<<"Address: "<< address<<std::endl;
        res->m_pduSession->upTunnel.address = stream.readOctetString(stream.read4I());
        std::cout << "Size of OctetString object: " << sizeof(res->m_pduSession->upTunnel.address) << " bytes" << std::endl;
        // Assuming m.m_pduSession->upTunnel.address is an OctetString
        for (size_t i = 0; i < sizeof(res->m_pduSession->upTunnel.address); ++i) {
            if (i != 0) {
                std::cout << ".";
            }
            std::cout << static_cast<int>(res->m_pduSession->upTunnel.address.data()[i]);
        }
        std::cout << std::endl;


        // Read GtpTunnel downTunnel
        res->m_pduSession->downTunnel.teid = stream.read4UI();
        std::cout<<"res->m_pduSession->downTunnel.teid: "<<res->m_pduSession->downTunnel.teid<<std::endl;
        res->m_pduSession->downTunnel.address = stream.readOctetString(stream.read4I());
        std::cout << "Size of OctetString object: " << sizeof(res->m_pduSession->downTunnel.address) << " bytes" << std::endl;
        //std::cout<<"Len: "<<len<<std::endl;
        for (size_t i = 0; i < sizeof(res->m_pduSession->downTunnel.address); ++i) {
            if (i != 0) {
                std::cout << ".";
            }
            std::cout << static_cast<int>(res->m_pduSession->downTunnel.address.data()[i]);
        }
        std::cout<<"GTP Tunnel Address (hex): ";
        for (size_t i = 0; i < sizeof(res->m_pduSession->downTunnel.address); ++i) {
            printf("%02x ", res->m_pduSession->downTunnel.address.data()[i]);
        }
        printf("\n");
        std::cout << std::endl;
        // Read QoS Flows
        int qosFlowCount = stream.read4I();
        std::cout << "List: " << qosFlowCount << std::endl;

        // Allocate space for qosFlows
        asn::Unique<ASN_NGAP_QosFlowSetupRequestList> newQosFlows(asn::New<ASN_NGAP_QosFlowSetupRequestList>());
        res->m_pduSession->qosFlows = std::move(newQosFlows);
        res->m_pduSession->qosFlows->list.array = new ASN_NGAP_QosFlowSetupRequestItem*[qosFlowCount];

        for (int iQos = 0; iQos < qosFlowCount; iQos++) {
            res->m_pduSession->qosFlows->list.array[iQos] = new ASN_NGAP_QosFlowSetupRequestItem();
            res->m_pduSession->qosFlows->list.array[iQos]->qosFlowIdentifier = stream.read4I();
            std::cout<<"res->m_pduSession->qosFlows->list.array[iQos]->qosFlowIdentifier: "<<res->m_pduSession->qosFlows->list.array[iQos]->qosFlowIdentifier<<std::endl;
        }
        res->m_pduSession->qosFlows->list.count = qosFlowCount;
        std::cout<<"res->m_pduSession->qosFlows->list.array[0]->qosFlowIdentifier: "<<res->m_pduSession->qosFlows->list.array[0]->qosFlowIdentifier<<std::endl;

        std::cout<<" Decoding is running@@@"<<std::endl;

        return res;

    }

    return nullptr;
}

} // namespace rls


#include "zeek/analyzer/protocol/tcp/TCP_Father.h"

#include <iostream>

#include "zeek/analyzer/protocol/tcp/Ambiguity.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"
#include "zeek/Sessions.h"


namespace zeek::analyzer::tcp {

/********************
 * Analyzer methods *
 ********************/

TCP_FatherAnalyzer::TCP_FatherAnalyzer(Connection *conn, bool robust)
: TransportLayerAnalyzer("TCPFather", conn) 
{
    TCP_Analyzer *ta = new TCP_Analyzer(conn, this);
    tcp_children.push_back(ta);
    robust_mode = robust;
    if (!robust_mode) {
        // set the ambiguity behaviors for non-robust mode
        for (int ambiguity_id = 0; ambiguity_id < AMBI_MAX; ambiguity_id++) {
            ta->ambiguity_behavior[ambiguity_id] = AMBI_BEHAV_OLD;
        }
    }
}

TCP_FatherAnalyzer::~TCP_FatherAnalyzer() 
{
    for (TCP_Analyzer *tcp_child : tcp_children) {
        assert(tcp_child->IsFinished());
        delete tcp_child;
    }
}

void TCP_FatherAnalyzer::Init()
{
    assert(tcp_children.size() == 1);

    Analyzer::Init();

    for (TCP_Analyzer *tcp_child : tcp_children) {
        tcp_child->Init();
    }
}

void TCP_FatherAnalyzer::Done()
{
    TransportLayerAnalyzer::Done();

    for (TCP_Analyzer *tcp_child : tcp_children) {
        if (!tcp_child->IsFinished())
            tcp_child->Done();
    }
}

void TCP_FatherAnalyzer::NextPacket(int len, const u_char* data, bool is_orig,
                uint64_t seq, const IP_Hdr* ip, int caplen)
{
    int i = 0;
    std::vector<TCP_Analyzer*> new_tcp_children;

    for (TCP_Analyzer *tcp_child : tcp_children) {
        if (tcp_child->CheckAmbiguity(data, len, caplen, is_orig)) {
            if (robust_mode) {
                // fork TCP Analyzer if there's any ambiguities with undefined behaviors
                for (int ambiguity_id = 0; ambiguity_id < AMBI_MAX; ambiguity_id++) {
                    if (tcp_child->curr_pkt_ambiguities[ambiguity_id]) {
                        //std::cout << "State " << i << ": found ambiguity: " << ambiguity_id << "\n";
                        if (tcp_child->ambiguity_behavior[ambiguity_id] == AMBI_BEHAV_UNDEF) {
                            // fork
                            //std::cout << "Forking State " << i << "\n";
                            TCP_Analyzer *tcp_child_forked = Fork(tcp_child);
                            new_tcp_children.push_back(tcp_child_forked);
                            
                            // set ambiguity behavior
                            // bind tcp_child to newer version, so older ambiguities should take new behaviors
                            for (int j = ambiguity_id; j >= 0; j--) {
                                assert(tcp_child->ambiguity_behavior[j] != AMBI_BEHAV_OLD);
                                tcp_child->ambiguity_behavior[j] = AMBI_BEHAV_NEW;
                            }
                            // bind tcp_child_forked to older version, so newer ambiguities should take old behaviors
                            for (int j = ambiguity_id; j < AMBI_MAX; j++) {
                                assert(tcp_child_forked->ambiguity_behavior[j] != AMBI_BEHAV_NEW);
                                tcp_child_forked->ambiguity_behavior[j] = AMBI_BEHAV_OLD;
                            }
                        }
                    }
                }
            }
        }
        i++;
    }

    // move newly forked tcp analyzers to tcp_children
    for (TCP_Analyzer *new_tcp_child : new_tcp_children) {
        tcp_children.push_back(new_tcp_child);
    }
    
    // handle the packet
    for (TCP_Analyzer *tcp_child : tcp_children) {
        tcp_child->NextPacket(len, data, is_orig, seq, ip, caplen);
    }
}

void TCP_FatherAnalyzer::NextStream(int len, const u_char* data, bool is_orig)
{
    std::cerr << "TCP_FatherAnalyzer::NextStream not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::NextUndelivered(uint64_t seq, int len, bool is_orig)
{
    std::cerr << "TCP_FatherAnalyzer::NextUndelivered not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::NextEndOfData(bool is_orig)
{
    std::cerr << "TCP_FatherAnalyzer::NextEndOfData not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::ForwardPacket(int len, const u_char* data,
                                       bool orig, uint64_t seq,
                                       const IP_Hdr* ip, int caplen)
{
    std::cerr << "TCP_FatherAnalyzer::ForwardPacket not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::ForwardStream(int len, const u_char* data, bool orig)
{
    std::cerr << "TCP_FatherAnalyzer::ForwardStream not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::ForwardUndelivered(uint64_t seq, int len, bool orig)
{
    std::cerr << "TCP_FatherAnalyzer::ForwardUndelivered not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::ForwardEndOfData(bool orig)
{
    std::cerr << "TCP_FatherAnalyzer::ForwardEndOfData not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq,
                   const IP_Hdr* ip, int caplen)
{
    std::cerr << "TCP_FatherAnalyzer::DeliverPacket not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::DeliverStream(int len, const u_char* data, bool orig)
{
    std::cerr << "TCP_FatherAnalyzer::DeliverStream not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::Undelivered(uint64_t seq, int len, bool orig)
{
    std::cerr << "TCP_FatherAnalyzer::Undelivered not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::FlipRoles()
{
    for (TCP_Analyzer *tcp_child : tcp_children) {
        tcp_child->FlipRoles();
    }
}

void TCP_FatherAnalyzer::SetSkip(bool do_skip)
{
    std::cerr << "TCP_FatherAnalyzer::SetSkip not implemented!\n";
    assert(false);
}

bool TCP_FatherAnalyzer::Skipping() const
{
    std::cerr << "TCP_FatherAnalyzer::Skipping not implemented!\n";
    assert(false);
}

bool TCP_FatherAnalyzer::IsAllChildFinished() const 
{
    bool ret = true;
    for (TCP_Analyzer *tcp_child : tcp_children) {
        ret &= tcp_child->IsFinished();
    }
    return ret;
}

bool TCP_FatherAnalyzer::Removing() const
{
    std::cerr << "TCP_FatherAnalyzer::Removing not implemented!\n";
    assert(false);
}

bool TCP_FatherAnalyzer::RemoveChildAnalyzer(analyzer::ID id)
{
    bool found = false;
    for (auto iter = tcp_children.begin(); iter != tcp_children.end(); ++iter) {
        TCP_Analyzer *tcp_child = *iter;
        if (tcp_child->GetID() == id) {
            if (!tcp_child->IsFinished())
                tcp_child->Done();
            found = true;
        }
    }
    if (IsAllChildFinished()) {
        sessions->Remove(Conn());
    }
    return found;
}

bool TCP_FatherAnalyzer::HasChildAnalyzer(Tag tag)
{
    std::cerr << "TCP_FatherAnalyzer::HasChildAnalyzer not implemented!\n";
    assert(false);
}

Analyzer* TCP_FatherAnalyzer::FindChild(analyzer::ID id)
{
    assert(tcp_children.size() == 1);
    return tcp_children.front()->FindChild(id);
}

Analyzer* TCP_FatherAnalyzer::FindChild(analyzer::Tag tag)
{
    assert(tcp_children.size() == 1);
    return tcp_children.front()->FindChild(tag);
}

const analyzer_list& TCP_FatherAnalyzer::GetChildren()
{
    assert(tcp_children.size() == 1);
    return tcp_children.front()->GetChildren();
}

void TCP_FatherAnalyzer::AddSupportAnalyzer(SupportAnalyzer* analyzer)
{
    std::cerr << "TCP_FatherAnalyzer::AddSupportAnalyzer not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::RemoveSupportAnalyzer(SupportAnalyzer* analyzer)
{
    std::cerr << "TCP_FatherAnalyzer::RemoveSupportAnalyzer not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::UpdateConnVal(RecordVal *conn_val)
{
    for (TCP_Analyzer *tcp_child : tcp_children) {
        tcp_child->UpdateConnVal(conn_val);
    }
}

RecordVal* TCP_FatherAnalyzer::BuildConnVal()
{
    std::cerr << "TCP_FatherAnalyzer::BuildConnVal not implemented!\n";
    assert(false);
}

const RecordValPtr& TCP_FatherAnalyzer::ConnVal()
{
    std::cerr << "TCP_FatherAnalyzer::ConnVal not implemented!\n";
    assert(false);
}

unsigned int TCP_FatherAnalyzer::MemoryAllocation() const
{
    std::cerr << "TCP_FatherAnalyzer::MemoryAllocation not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::AddTimer(analyzer_timer_func timer, double t, bool do_expire,
                                  detail::TimerType type)
{
    std::cerr << "TCP_FatherAnalyzer::AddTimer not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::CancelTimers()
{
    for (TCP_Analyzer *tcp_child : tcp_children) {
        tcp_child->CancelTimers();
    }
}

void TCP_FatherAnalyzer::RemoveTimer(detail::Timer* t)
{
    std::cerr << "TCP_FatherAnalyzer::RemoveTimer not implemented!\n";
    assert(false);
}

bool TCP_FatherAnalyzer::HasSupportAnalyzer(const Tag& tag, bool orig)
{
    std::cerr << "TCP_FatherAnalyzer::HasSupportAnalyzer not implemented!\n";
    assert(false);
}

SupportAnalyzer* TCP_FatherAnalyzer::FirstSupportAnalyzer(bool orig)
{
    std::cerr << "TCP_FatherAnalyzer::FirstSupportAnalyzer not implemented!\n";
    assert(false);
}

bool TCP_FatherAnalyzer::AddChildAnalyzer(Analyzer *analyzer, bool init)
{
    assert(tcp_children.size() == 1);
    bool ret = false;
    bool first = true;
    for (TCP_Analyzer *tcp_child : tcp_children) {
        bool tmp = tcp_child->AddChildAnalyzer(analyzer, init);
        assert(first || tmp == ret);
        ret |= tmp;
        first = false;
    }
    return ret;
}

void TCP_FatherAnalyzer::InitChildren()
{
    assert(tcp_children.size() == 1);
    for (TCP_Analyzer *tcp_child : tcp_children) {
        tcp_child->InitChildren();
    }
}

void TCP_FatherAnalyzer::AppendNewChildren()
{
    for (TCP_Analyzer *tcp_child : tcp_children) {
        tcp_child->AppendNewChildren();
    }
}

bool TCP_FatherAnalyzer::RemoveChild(const analyzer_list& tcp_children, ID id)
{
    std::cerr << "TCP_FatherAnalyzer::RemoveChild not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::DeleteChild(analyzer_list::iterator i)
{
    std::cerr << "TCP_FatherAnalyzer::DeleteChild not implemented!\n";
    assert(false);
}

/**********************************
 * TransportLayerAnalyzer methods *
 **********************************/

void TCP_FatherAnalyzer::SetContentsFile(unsigned int direction, FilePtr f)
{
    std::cerr << "TCP_FatherAnalyzer::SetContentsFile not implemented!\n";
    assert(false);
}

FilePtr TCP_FatherAnalyzer::GetContentsFile(unsigned int direction) const
{
    std::cerr << "TCP_FatherAnalyzer::GetContentsFile not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::SetPIA(analyzer::pia::PIA* arg_PIA)
{
    std::cerr << "TCP_FatherAnalyzer::SetPIA not implemented!\n";
    assert(false);
}

analyzer::pia::PIA* TCP_FatherAnalyzer::GetPIA() const
{
    std::cerr << "TCP_FatherAnalyzer::GetPIA not implemented!\n";
    assert(false);
}

/************************
 * TCP_Analyzer methods *
 ************************/

void TCP_FatherAnalyzer::EnableReassembly() 
{
    assert(tcp_children.size() == 1);
    tcp_children.front()->EnableReassembly();
}

void TCP_FatherAnalyzer::AddChildPacketAnalyzer(Analyzer *analyzer)
{
    assert(tcp_children.size() == 1);
    for (TCP_Analyzer *tcp_child : tcp_children) {
        tcp_child->AddChildPacketAnalyzer(analyzer);
    }
}

/******************************
 * TCP_FatherAnalyzer methods *
 ******************************/

TCP_Analyzer* TCP_FatherAnalyzer::Fork(TCP_Analyzer* ta)
{
    //ta->DumpAnalyzerTree();
    TCP_Analyzer *copy = new TCP_Analyzer(ta);
    //copy->DumpAnalyzerTree();

    return copy;
}

} // namespace zeek::analyzer::tcp

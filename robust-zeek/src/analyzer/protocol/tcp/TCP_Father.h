// The father class of TCP_Analyzer. It forks TCP_analyzer.

# pragma once

#include "zeek/analyzer/Analyzer.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace zeek::analyzer::tcp {

class TCP_FatherAnalyzer final : public TransportLayerAnalyzer {
public:
    explicit TCP_FatherAnalyzer(Connection *conn, bool robust = true);
    ~TCP_FatherAnalyzer() override;

    /* Analyzer methods */
    void Init() override;

    void Done() override;

    void NextPacket(int len, const u_char* data, bool is_orig,
			uint64_t seq = -1, const IP_Hdr* ip = nullptr, int caplen = 0) override;

    void NextStream(int len, const u_char* data, bool is_orig) override;

    void NextUndelivered(uint64_t seq, int len, bool is_orig) override;

    void NextEndOfData(bool is_orig) override;

    void ForwardPacket(int len, const u_char* data,
                       bool orig, uint64_t seq,
                       const IP_Hdr* ip, int caplen) override;

    void ForwardStream(int len, const u_char* data, bool orig) override;

    void ForwardUndelivered(uint64_t seq, int len, bool orig) override;

    void ForwardEndOfData(bool orig) override;

    void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq,
                       const IP_Hdr* ip, int caplen) override;

    void DeliverStream(int len, const u_char* data, bool orig) override;

    void Undelivered(uint64_t seq, int len, bool orig) override;

    void FlipRoles() override;

    void SetSkip(bool do_skip) override;

    bool Skipping() const override;

    bool IsAllChildFinished() const;

    bool Removing() const override;

    bool RemoveChildAnalyzer(analyzer::ID id) override;

    bool HasChildAnalyzer(Tag tag) override;

    Analyzer* FindChild(analyzer::ID id) override;

    Analyzer* FindChild(analyzer::Tag tag) override;

    const analyzer_list& GetChildren() override;

    void AddSupportAnalyzer(SupportAnalyzer* analyzer) override;

    void RemoveSupportAnalyzer(SupportAnalyzer* analyzer) override;

    void UpdateConnVal(RecordVal *conn_val) override;

    RecordVal* BuildConnVal() override;

    const RecordValPtr& ConnVal() override;

    unsigned int MemoryAllocation() const override;

    void AddTimer(analyzer_timer_func timer, double t, bool do_expire,
                  detail::TimerType type) override;

    void CancelTimers() override;

    void RemoveTimer(detail::Timer* t) override;

    bool HasSupportAnalyzer(const Tag& tag, bool orig) override;

    SupportAnalyzer* FirstSupportAnalyzer(bool orig) override;

    bool AddChildAnalyzer(Analyzer* analyzer, bool init) override;

    void InitChildren() override;

    void AppendNewChildren() override;

    bool RemoveChild(const analyzer_list& children, ID id) override;

    void DeleteChild(analyzer_list::iterator i) override;

    /* TransportLayerAnalyzer methods */

    bool IsReuse(double t, const u_char* pkt) override {
        // Cannot process connection reuse with state forking
        return false;
    }

    void SetContentsFile(unsigned int direction, FilePtr f) override;

    FilePtr GetContentsFile(unsigned int direction) const override;

    void SetPIA(analyzer::pia::PIA* arg_PIA) override;

    analyzer::pia::PIA* GetPIA() const override;

    /* TCP_Analyzer methods */

    void EnableReassembly();

    void AddChildPacketAnalyzer(Analyzer *analyzer);

    static analyzer::Analyzer* Instantiate(Connection* conn)
        { return new TCP_FatherAnalyzer(conn); }

private:
    TCP_Analyzer* Fork(TCP_Analyzer *ta);

    std::vector<TCP_Analyzer*> tcp_children;

    bool robust_mode;
};


} // namespace zeek::analyzer::tcp

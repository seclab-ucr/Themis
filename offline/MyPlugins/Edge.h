
#ifndef S2E_PLUGINS_EDGE_H
#define S2E_PLUGINS_EDGE_H


struct Edge {
    uint64_t src;
    uint64_t dst;

    Edge() : src(0), dst(0) {
    }

    Edge(uint64_t s, uint64_t d) : src(s), dst(d) {
    }

    bool operator==(const Edge &other) const {
        return src == other.src && dst == other.dst;
    }
};


namespace std {

template<>
struct hash<Edge> {
    size_t operator()(const Edge& e) const {
        return hash<uint64_t>()(e.src) ^ hash<uint64_t>()(e.dst);
    }
};

}


#endif // S2E_PLUGINS_EDGE_H

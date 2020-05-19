package combinator

import (
	"fmt"
	"math"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/proto"
)

type ASnote struct {
	Note string
}

type ASGeo struct {
	locations []GeoLoc
}

type GeoLoc struct {
	Latitude  float32 `capnp:"latitude"`
	Longitude float32 `capnp:"longitude"`
	Address   string  `capnp:"address"`
}

func (s *GeoLoc) ProtoId() proto.ProtoIdType {
	return proto.PathMetadata_Geo_GPSData_TypeID
}

func (s *GeoLoc) String() string {
	return fmt.Sprintf("Latitude: %f\nLongitude: %f\nAddress: %s\n",
		s.Latitude, s.Longitude, s.Address)
}

type ASLatency struct {
	IntraLatency uint16
	InterLatency uint16
	PeerLatency  uint16
}

type ASHops struct {
	Hops uint8
}

type ASLink struct {
	InterLinkType uint16
	PeerLinkType  uint16
}

type ASBandwidth struct {
	IntraBW uint32
	InterBW uint32
}

type DenseASLinkType struct {
	InterLinkType uint16     `capnp:"interLinkType"`
	PeerLinkType  uint16     `capnp:"peerLinkType"`
	RawIA         addr.IAInt `capnp:"isdas"`
}

func (s *DenseASLinkType) ProtoId() proto.ProtoIdType {
	return proto.PathMetadata_InterfaceLinkType_TypeID
}

func (s *DenseASLinkType) String() string {
	return fmt.Sprintf("InterLinkType: %d\nPeerLinkType: %d\nISD: %d\nAS: %d\n",
		s.InterLinkType, s.PeerLinkType, s.RawIA.IA().I, s.RawIA.IA().A)
}

type DenseGeo struct {
	RouterLocations []GeoLoc   `capnp:"routerLocations"`
	RawIA           addr.IAInt `capnp:"isdas"`
}

func (s *DenseGeo) ProtoId() proto.ProtoIdType {
	return proto.PathMetadata_Geo_TypeID
}

func (s *DenseGeo) String() string {
	return fmt.Sprintf("RouterLocations: %v\nISD: %d\nAS: %d\n",
		s.RouterLocations, s.RawIA.IA().I, s.RawIA.IA().A)
}

type DenseNote struct {
	Note  string     `capnp:"note"`
	RawIA addr.IAInt `capnp:"isdas"`
}

func (s *DenseNote) ProtoId() proto.ProtoIdType {
	return proto.PathMetadata_Note_TypeID
}

func (s *DenseNote) String() string {
	return fmt.Sprintf("Text: %s\nISD: %d\nAS: %d\n",
		s.Note, s.RawIA.IA().I, s.RawIA.IA().A)
}

type RawPathMetadata struct {
	ASLatencies  map[addr.IA]ASLatency
	ASBandwidths map[addr.IA]ASBandwidth
	ASHops       map[addr.IA]ASHops
	Geo          map[addr.IA]ASGeo
	Links        map[addr.IA]ASLink
	Notes        map[addr.IA]ASnote
}

// PathMetadata is the condensed form of metadata retaining only the most important values.
type PathMetadata struct {
	TotalLatency uint16            `capnp:"totalLatency"`
	TotalHops    uint8             `capnp:"totalHops"`
	MinOfMaxBWs  uint32            `capnp:"bandwidthBottleneck"`
	LinkTypes    []DenseASLinkType `capnp:"linkTypes"`
	Locations    []DenseGeo        `capnp:"asLocations"`
	Notes        []DenseNote       `capnp:"notes"`
}

func (s *PathMetadata) ProtoId() proto.ProtoIdType {
	return proto.PathMetadata_TypeID
}

func (s *PathMetadata) String() string {
	return fmt.Sprintf("TotalLatency: %v\nTotalHops: %v\n"+
		"BandwidthBottleneck: %v\nLinkTypes: %v\nASLocations: %v\nNotes: %v\n",
		s.TotalLatency, s.TotalHops, s.MinOfMaxBWs, s.LinkTypes, s.Locations,
		s.Notes)
}

// Condensemetadata takes RawPathMetadata and extracts/condenses
// the most important values to be transmitted to SCIOND
func (data *RawPathMetadata) Condensemetadata() *PathMetadata {
	ret := &PathMetadata{
		TotalLatency: 0,
		TotalHops:    0,
		MinOfMaxBWs:  math.MaxUint32,
	}

	for _, val := range data.ASBandwidths {
		var asmaxbw uint32 = math.MaxUint32
		if val.IntraBW > 0 {
			asmaxbw = uint32(math.Min(float64(val.IntraBW), float64(asmaxbw)))
		}
		if val.InterBW > 0 {
			asmaxbw = uint32(math.Min(float64(val.InterBW), float64(asmaxbw)))
		}
		if asmaxbw < (math.MaxUint32) {
			ret.MinOfMaxBWs = uint32(math.Min(float64(ret.MinOfMaxBWs), float64(asmaxbw)))
		}
	}

	if !(ret.MinOfMaxBWs < math.MaxUint32) {
		ret.MinOfMaxBWs = 0
	}

	for _, val := range data.ASLatencies {
		ret.TotalLatency += val.InterLatency + val.IntraLatency + val.PeerLatency
	}

	for _, val := range data.ASHops {
		ret.TotalHops += val.Hops
	}

	for ia, note := range data.Notes {
		ret.Notes = append(ret.Notes, DenseNote{
			Note:  note.Note,
			RawIA: ia.IAInt(),
		})
	}

	for ia, loc := range data.Geo {
		ret.Locations = append(ret.Locations, DenseGeo{
			RawIA:           ia.IAInt(),
			RouterLocations: loc.locations,
		})
	}

	for ia, link := range data.Links {
		ret.LinkTypes = append(ret.LinkTypes, DenseASLinkType{
			InterLinkType: link.InterLinkType,
			PeerLinkType:  link.PeerLinkType,
			RawIA:         ia.IAInt(),
		})
	}

	return ret
}

type ASEntryList struct {
	Ups      []*seg.ASEntry
	Cores    []*seg.ASEntry
	Downs    []*seg.ASEntry
	UpPeer   int
	DownPeer int
}

func (solution *PathSolution) collectMetadata() *PathMetadata{
	asEntries := solution.GatherASEntries()
	rawMeta := CombineSegments(asEntries)
	res := rawMeta.Condensemetadata()
	return res
}

func (solution *PathSolution) GatherASEntries() *ASEntryList {
	var res ASEntryList
	for _, solEdge := range solution.edges {
		asEntries := solEdge.segment.ASEntries
		currType := solEdge.segment.Type
		for asEntryIdx := len(asEntries) - 1; asEntryIdx >= solEdge.edge.Shortcut; asEntryIdx-- {
			asEntry := asEntries[asEntryIdx]
			switch currType {
			case proto.PathSegType_up:
				res.Ups = append(res.Ups, asEntry)
			case proto.PathSegType_core:
				res.Cores = append(res.Cores, asEntry)
			case proto.PathSegType_down:
				res.Downs = append(res.Downs, asEntry)
			}
		}
		switch currType {
		case proto.PathSegType_up:
			res.UpPeer = solEdge.edge.Peer
		case proto.PathSegType_down:
			res.DownPeer = solEdge.edge.Peer
		}
	}
	return &res
}

func ExtractPeerdata(res *RawPathMetadata, asEntry *seg.ASEntry,
	peerIfID common.IFIDType, includePeer bool) {

	ia := asEntry.IA()
	staticInfo := asEntry.Exts.StaticInfo
	for i := 0; i < len(staticInfo.Latency.Peerlatencies); i++ {
		if staticInfo.Latency.Peerlatencies[i].IfID == peerIfID {
			if includePeer {
				res.ASLatencies[ia] = ASLatency{
					IntraLatency: staticInfo.Latency.Peerlatencies[i].IntraDelay,
					InterLatency: staticInfo.Latency.Egresslatency,
					PeerLatency:  staticInfo.Latency.Peerlatencies[i].Interdelay,
				}
			} else {
				res.ASLatencies[ia] = ASLatency{
					IntraLatency: staticInfo.Latency.Peerlatencies[i].IntraDelay,
					InterLatency: staticInfo.Latency.Egresslatency,
				}
			}
		}
	}
	for i := 0; i < len(staticInfo.Linktype.Peerlinks); i++ {
		if staticInfo.Linktype.Peerlinks[i].IfID == peerIfID {
			if includePeer {
				res.Links[ia] = ASLink{
					InterLinkType: staticInfo.Linktype.EgressLinkType,
					PeerLinkType:  staticInfo.Linktype.Peerlinks[i].LinkType,
				}
			} else {
				res.Links[ia] = ASLink{
					InterLinkType: staticInfo.Linktype.EgressLinkType,
				}
			}
		}
	}
	for i := 0; i < len(staticInfo.Bandwidth.Bandwidths); i++ {
		if staticInfo.Bandwidth.Bandwidths[i].IfID == peerIfID {
			res.ASBandwidths[ia] = ASBandwidth{
				IntraBW: staticInfo.Bandwidth.Bandwidths[i].BW,
				InterBW: staticInfo.Bandwidth.EgressBW,
			}
		}
	}
	for i := 0; i < len(staticInfo.Hops.InterfaceHops); i++ {
		if staticInfo.Hops.InterfaceHops[i].IfID == peerIfID {
			res.ASHops[ia] = ASHops{
				Hops: staticInfo.Hops.InterfaceHops[i].Hops,
			}
		}
	}
	res.Geo[ia] = getGeo(asEntry)
	res.Notes[ia] = ASnote{
		Note: staticInfo.Note,
	}
}

func ExtractSingleSegmentFinalASData(res *RawPathMetadata, asEntry *seg.ASEntry) {
	ia := asEntry.IA()
	staticInfo := asEntry.Exts.StaticInfo
	res.ASLatencies[ia] = ASLatency{
		InterLatency: staticInfo.Latency.Egresslatency,
		PeerLatency:  0,
	}
	res.Links[ia] = ASLink{
		InterLinkType: staticInfo.Linktype.EgressLinkType,
	}
	res.ASBandwidths[ia] = ASBandwidth{
		InterBW: staticInfo.Bandwidth.EgressBW,
	}
	res.ASHops[ia] = ASHops{}
	res.Geo[ia] = getGeo(asEntry)
	res.Notes[ia] = ASnote{
		Note: staticInfo.Note,
	}
}

func ExtractNormaldata(res *RawPathMetadata, asEntry *seg.ASEntry) {
	ia := asEntry.IA()
	staticInfo := asEntry.Exts.StaticInfo
	res.ASLatencies[ia] = ASLatency{
		IntraLatency: staticInfo.Latency.IngressToEgressLatency,
		InterLatency: staticInfo.Latency.Egresslatency,
		PeerLatency:  0,
	}
	res.Links[ia] = ASLink{
		InterLinkType: staticInfo.Linktype.EgressLinkType,
	}
	res.ASBandwidths[ia] = ASBandwidth{
		IntraBW: staticInfo.Bandwidth.IngressToEgressBW,
		InterBW: staticInfo.Bandwidth.EgressBW,
	}
	res.ASHops[ia] = ASHops{
		Hops: staticInfo.Hops.InToOutHops,
	}
	res.Geo[ia] = getGeo(asEntry)
	res.Notes[ia] = ASnote{
		Note: staticInfo.Note,
	}
}

func ExtractUpOverdata(res *RawPathMetadata, oldASEntry *seg.ASEntry, newASEntry *seg.ASEntry) {
	ia := newASEntry.IA()
	staticInfo := oldASEntry.Exts.StaticInfo
	hopEntry := newASEntry.HopEntries[0]
	hf, _ := hopEntry.HopField()
	newIngressIfID := hf.ConsIngress
	for i := 0; i < len(staticInfo.Latency.Childlatencies); i++ {
		if staticInfo.Latency.Childlatencies[i].IfID == newIngressIfID {
			res.ASLatencies[ia] = ASLatency{
				IntraLatency: staticInfo.Latency.Childlatencies[i].Intradelay,
				InterLatency: staticInfo.Latency.Egresslatency,
			}
		}
	}
	res.Links[ia] = ASLink{
		InterLinkType: staticInfo.Linktype.EgressLinkType,
	}

	for i := 0; i < len(staticInfo.Bandwidth.Bandwidths); i++ {
		if staticInfo.Bandwidth.Bandwidths[i].IfID == newIngressIfID {
			res.ASBandwidths[ia] = ASBandwidth{
				IntraBW: staticInfo.Bandwidth.Bandwidths[i].BW,
				InterBW: staticInfo.Bandwidth.EgressBW,
			}
		}
	}
	for i := 0; i < len(staticInfo.Hops.InterfaceHops); i++ {
		if staticInfo.Hops.InterfaceHops[i].IfID == newIngressIfID {
			res.ASHops[ia] = ASHops{
				Hops: staticInfo.Hops.InterfaceHops[i].Hops,
			}
		}
	}
	res.Geo[ia] = getGeo(newASEntry)
	res.Notes[ia] = ASnote{
		Note: staticInfo.Note,
	}
}

func ExtractCoreOverdata(res *RawPathMetadata, oldASEntry *seg.ASEntry, newASEntry *seg.ASEntry) {
	ia := newASEntry.IA()
	staticInfo := newASEntry.Exts.StaticInfo
	oldSI := oldASEntry.Exts.StaticInfo
	hopEntry := oldASEntry.HopEntries[0]
	hf, _ := hopEntry.HopField()
	oldEgressIfID := hf.ConsEgress
	for i := 0; i < len(staticInfo.Latency.Childlatencies); i++ {
		if staticInfo.Latency.Childlatencies[i].IfID == oldEgressIfID {
			res.ASLatencies[ia] = ASLatency{
				IntraLatency: staticInfo.Latency.Childlatencies[i].Intradelay,
				InterLatency: staticInfo.Latency.Egresslatency,
				PeerLatency:  oldSI.Latency.Egresslatency,
			}
		}
	}
	res.Links[ia] = ASLink{
		InterLinkType: staticInfo.Linktype.EgressLinkType,
		PeerLinkType:  oldSI.Linktype.EgressLinkType,
	}

	for i := 0; i < len(staticInfo.Bandwidth.Bandwidths); i++ {
		if staticInfo.Bandwidth.Bandwidths[i].IfID == oldEgressIfID {
			res.ASBandwidths[ia] = ASBandwidth{
				IntraBW: staticInfo.Bandwidth.Bandwidths[i].BW,
				InterBW: staticInfo.Bandwidth.EgressBW,
			}
		}
	}
	for i := 0; i < len(staticInfo.Hops.InterfaceHops); i++ {
		if staticInfo.Hops.InterfaceHops[i].IfID == oldEgressIfID {
			res.ASHops[ia] = ASHops{
				Hops: staticInfo.Hops.InterfaceHops[i].Hops,
			}
		}
	}
	res.Geo[ia] = getGeo(newASEntry)
	res.Notes[ia] = ASnote{
		Note: staticInfo.Note,
	}
}

func CombineSegments(ASes *ASEntryList) *RawPathMetadata {
	var lastUpASEntry *seg.ASEntry
	var lastCoreASEntry *seg.ASEntry
	res := &RawPathMetadata{
		ASLatencies:  make(map[addr.IA]ASLatency),
		ASBandwidths: make(map[addr.IA]ASBandwidth),
		ASHops:       make(map[addr.IA]ASHops),
		Geo:          make(map[addr.IA]ASGeo),
		Links:        make(map[addr.IA]ASLink),
		Notes:        make(map[addr.IA]ASnote),
	}
	// Go through ASEntries in the up segment (except for the first one)
	// and extract the static info data from them
	for idx := 0; idx < len(ASes.Ups); idx++ {
		asEntry := ASes.Ups[idx]
		s := asEntry.Exts.StaticInfo
		if s == nil {
			continue
		}
		if idx == 0 {
			res.Geo[asEntry.IA()] = getGeo(asEntry)
		} else if idx < (len(ASes.Ups) - 1) {
			ExtractNormaldata(res, asEntry)
		} else {
			if (len(ASes.Cores) == 0) && (len(ASes.Downs) == 0) {
				ExtractSingleSegmentFinalASData(res, asEntry)
			} else if ASes.UpPeer != 0 {
				peerEntry := asEntry.HopEntries[ASes.UpPeer]
				PE, _ := peerEntry.HopField()
				peerIfID := PE.ConsIngress
				ExtractPeerdata(res, asEntry, peerIfID, false)
			} else {
				// If the last up AS is not involved in peering,
				// do nothing except store the as in LastUpASEntry
				lastUpASEntry = asEntry
			}
		}
	}
	// Go through ASEntries in the core segment
	// and extract the static info data from them
	for idx := 0; idx < len(ASes.Cores); idx++ {
		asEntry := ASes.Cores[idx]
		s := asEntry.Exts.StaticInfo
		if s == nil {
			continue
		}
		if idx == 0 {
			if len(ASes.Ups) > 0 {
				// We're in the AS where we cross over from the up to the core segment
				ExtractUpOverdata(res, lastUpASEntry, asEntry)
			} else {
				// This is the first AS in the path, so we only extract its geodata
				res.Geo[asEntry.IA()] = getGeo(asEntry)
			}
		} else if idx < (len(ASes.Cores) - 1) {
			ExtractNormaldata(res, asEntry)
		} else {
			// If we're in the last AS of the segment
			// only set LastCoreASEntry
			lastCoreASEntry = asEntry
			if len(ASes.Downs) == 0 {
				ExtractNormaldata(res, asEntry)
			}
		}
	}

	// Go through ASEntries in the down segment except for the first one
	// and extract the static info data from them
	for idx := 0; idx < len(ASes.Downs); idx++ {
		asEntry := ASes.Downs[idx]
		s := asEntry.Exts.StaticInfo
		if s == nil {
			continue
		}
		if idx == 0 {
			res.Geo[asEntry.IA()] = getGeo(asEntry)
		} else if idx < (len(ASes.Downs) - 1) {
			ExtractNormaldata(res, asEntry)
		} else {
			if ASes.DownPeer != 0 {
				// We're in the AS where we peered over from the up to the down segment
				peerEntry := asEntry.HopEntries[ASes.UpPeer]
				PE, _ := peerEntry.HopField()
				peerIfID := PE.ConsIngress
				ExtractPeerdata(res, asEntry, peerIfID, true)
			} else {
				if len(ASes.Cores) > 0 {
					// We're in the AS where we cross over from the core to the down segment
					ExtractCoreOverdata(res, lastCoreASEntry, asEntry)
				}
				if (len(ASes.Ups) > 0) && (len(ASes.Cores) == 0) {
					// We're in the AS where we cross over from the up to
					// the down segment via a shortcut (analogous to crossing
					// over from core to down, thus we use ExtractCoreOverdata())
					ExtractCoreOverdata(res, lastUpASEntry, asEntry)
				}
				if (len(ASes.Ups) == 0) && (len(ASes.Cores) == 0) {
					ExtractSingleSegmentFinalASData(res, asEntry)
				}
			}
		}
	}
	return res
}

func getGeo(asEntry *seg.ASEntry) ASGeo {
	var locations []GeoLoc
	for _, loc := range asEntry.Exts.StaticInfo.Geo.Locations {
		locations = append(locations, GeoLoc{
			Latitude:  loc.GPSData.Latitude,
			Longitude: loc.GPSData.Longitude,
			Address:   loc.GPSData.Address,
		})
	}
	res := ASGeo{
		locations: locations,
	}
	return res
}

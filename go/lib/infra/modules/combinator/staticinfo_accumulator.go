package combinator

import (
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
	Latitude float32
	Longitude float32
	CivAddr string
}

type ASDelay struct {
	Intradelay uint16
	Interdelay uint16
	Peerdelay uint16
}

type ASHops struct {
	Hops uint8
}

type ASLink struct {
	InterLinkType uint16
	PeerLinkType uint16
}

type ASBandwidth struct {
	IntraBW uint32
	InterBW uint32
}

type Pathmetadata struct {
	UpASes []addr.IA
	CoreASes []addr.IA
	DownASes []addr.IA
	SingleDelays map[addr.IA]ASDelay
	Singlebw map[addr.IA]ASBandwidth
	SingleHops map[addr.IA]ASHops
	Internalhops map[addr.IA]uint8
	Geo map[addr.IA]ASGeo
	Links map[addr.IA]ASLink
	Notes map[addr.IA]ASnote
}

// Condensed form of metadata retaining only most important values.
type Densemetadata struct {
	ASes []addr.IA
	TotalDelay uint16
	TotalHops uint8
	MinOfMaxBWs uint32
	LinkTypes map[addr.IA]ASLink
	Locations map[addr.IA]ASGeo
	Notes map[addr.IA]string
}


func (data *Pathmetadata) Condensemetadata() *Densemetadata{
	ret := &Densemetadata{
		TotalDelay: 0,
		TotalHops: 0,
		MinOfMaxBWs: math.MaxUint32,
	}

	for _, val := range data.Singlebw{
		var asmaxbw uint32
		asmaxbw = math.MaxUint32
		if(val.IntraBW>0){
			asmaxbw = uint32(math.Min(float64(val.IntraBW),float64(asmaxbw)))
		}
		if(val.InterBW>0){
			asmaxbw = uint32(math.Min(float64(val.InterBW),float64(asmaxbw)))
		}
		if(asmaxbw<(math.MaxUint32)){
			ret.MinOfMaxBWs = uint32(math.Min(float64(ret.MinOfMaxBWs),float64(asmaxbw)))
		}
	}

	if !(ret.MinOfMaxBWs<math.MaxUint32){
		ret.MinOfMaxBWs = 0
	}

	for _, val := range data.SingleDelays{
		ret.TotalDelay += val.Interdelay + val.Intradelay + val.Peerdelay
	}

	for  _, val := range data.SingleHops{
		ret.TotalHops += val.Hops
	}

	for IA, note := range data.Notes{
		ret.Notes[IA] = note.Note
	}

	for IA, loc := range data.Geo{
		ret.Locations[IA] = loc
	}
	for IA, link := range data.Links{
		ret.LinkTypes[IA] =  link
	}

	for i := 0; i<len(data.UpASes); i++  {
		ret.ASes = append(ret.ASes, data.UpASes[i])
	}
	for i := len(data.CoreASes)-1; i>=0; i--  {
		ret.ASes = append(ret.ASes, data.CoreASes[i])
	}
	for i:=len(data.DownASes)-1;i>=0;i--  {
		ret.ASes = append(ret.ASes, data.DownASes[i])
	}

	return ret
}

func (solution *PathSolution) Assemblepcbmetadata() *Pathmetadata{
	UpOver := false
	DownOver := false
	PeerOver := false
	var DownOverifID common.IFIDType
	var PeerOverifID common.IFIDType
	var UpOverEntry *seg.ASEntry
	iscoreseg := proto.PathSegType_core
	var res Pathmetadata
	/*
		Iterate over solutionEdges in solution, start in last ASEntry, go until entry with index "shortcut"
		While not shortcut, simply assemble metadata normally by using intoout metrics in the ASEntry's staticinfoextn.
		If index == shortcut, check if "normal" shortcut or peering shortcut (if peer != 0) and treat accordingly.
		Also make sure to treat the first entry in the up and down segs (i.e. first and last ASes on the path)
		specially, since there is no metadata to collect on those ASes.
	*/
	for _, solEdge := range solution.edges{
		asEntries := solEdge.segment.ASEntries
		for asEntryIdx := len(asEntries) - 1; asEntryIdx >= solEdge.edge.Shortcut; asEntryIdx-- {
			if (solEdge.segment.Type == iscoreseg){
				res.CoreASes = append(res.CoreASes, asEntries[asEntryIdx].IA())
			}
			if solEdge.segment.IsDownSeg(){
				res.DownASes = append(res.DownASes, asEntries[asEntryIdx].IA())
			}
			if (!(solEdge.segment.Type == iscoreseg)) && (!(solEdge.segment.IsDownSeg())){
				res.UpASes = append(res.UpASes, asEntries[asEntryIdx].IA())
			}
			if (asEntryIdx>solEdge.edge.Shortcut) {
				asEntry := asEntries[asEntryIdx]
				hopEntry := asEntry.HopEntries[0]
				HF,_ := hopEntry.HopField()
				inIFID := HF.ConsIngress
				var SI *seg.StaticInfoExtn
				SI = asEntry.Exts.StaticInfo
				// If we're in the middle of a segment, simply take data from staticinfoextn in
				// the corresponding ASEntry and put it into res
				if !(asEntryIdx==(len(asEntries)-1)){
					IA := asEntry.IA()
					res.SingleDelays[IA] = ASDelay{
						Intradelay: SI.Latency.IngressToEgressLatency,
						Interdelay: SI.Latency.Egresslatency,
						Peerdelay:  0,
					}
					res.SingleHops[IA] = ASHops{
						Hops: SI.Hops.InToOutHops,
					}
					res.Singlebw[IA] = ASBandwidth{
						IntraBW: SI.Bandwidth.IngressToEgressBW,
						InterBW: SI.Bandwidth.EgressBW,
					}
					res.Links[IA] = ASLink{
						InterLinkType: SI.Linktype.EgressLinkType,
					}
					res.Geo[IA] = ASGeo{
						locations: gathergeo(SI),
					}
					res.Notes[IA] = ASnote{
						Note: SI.Note,
					}
				}
				// If we're in the last AS of a coresegment (i.e. the first inspected entry),
				// set the DownOver flag and remember the ifID of the ingress interface.
				if (solEdge.segment.Type == iscoreseg) && (asEntryIdx==(len(asEntries)-1)){
					DownOver = true
					DownOverifID = inIFID
				}
				// If we're in the first AS in an up or last AS in a down segment (i.e. first
				// inspected entry in both cases), leave all entries empty except for geo.
				if (!(solEdge.segment.Type == iscoreseg)) && (asEntryIdx==(len(asEntries)-1)){
					IA := asEntry.IA()
					res.SingleDelays[IA] = ASDelay{}
					res.SingleHops[IA] = ASHops{}
					res.Singlebw[IA] = ASBandwidth{}
					res.Links[IA] = ASLink{}
					res.Geo[IA] = ASGeo{
						locations: gathergeo(SI),
					}
					res.Notes[IA] = ASnote{}
				}
			} else {
				asEntry := asEntries[asEntryIdx]
				hopEntry := asEntry.HopEntries[0]
				var SI *seg.StaticInfoExtn
				SI = asEntry.Exts.StaticInfo
				if (solEdge.edge.Peer != 0) {
					peerEntry := asEntry.HopEntries[solEdge.edge.Peer]
					PE, _ := peerEntry.HopField()
					inIFID := PE.ConsIngress
					// Treat peering link crossover case by simply adding everything as we would in the case of
					// an AS somewhere in the middle of a segment, with the exception that the peering interface is
					// used as the ingress interface. Set peerover flag.
					IA := asEntry.IA()
					// If res.Peerover is set, include the data about the peering connection for LinkType and
					// Latency, otherwise ignore it (so it isn't included twice)
					var currDelay ASDelay
					var currLinks ASLink
					if PeerOver {
						intraDelay, peerDelay := gatherpeeringlatencydata(SI, PeerOverifID)
						currDelay = ASDelay{
							Intradelay: intraDelay,
							Peerdelay: peerDelay,
						}
						currLinks = ASLink{
							PeerLinkType:  gatherpeeroverlink(SI, PeerOverifID),
						}
						PeerOver = false
					} else {
						currDelay = ASDelay{
							Intradelay: gatherxoverlatency(SI, inIFID),
						}
						PeerOver = true
					}
					currDelay.Interdelay = SI.Latency.Egresslatency
					currLinks.InterLinkType = SI.Linktype.EgressLinkType
					res.SingleDelays[IA] = currDelay
					res.Links[IA] = currLinks

					res.Singlebw[IA] = ASBandwidth{
						IntraBW: gatherxoverbw(SI, inIFID),
						InterBW: SI.Bandwidth.EgressBW,
					}
					res.SingleHops[IA] = ASHops{
						Hops: gatherxoverhops(SI, inIFID),
					}
					res.Geo[IA] = ASGeo{
						locations: gathergeo(SI),
					}
					res.Notes[IA] = ASnote{
						Note:SI.Note,
					}
					PeerOverifID = peerEntry.RemoteInIF
					continue
				} else {
					// If we're in the AS where we cross over from an up segment
					// (i.e. res.Upover is set), fill pathmetadata using UpOverentry
					if UpOver {
						var oldSI *seg.StaticInfoExtn
						oldSI = UpOverEntry.Exts.StaticInfo
						IA := asEntry.IA()
						HF,_ := hopEntry.HopField()
						egIFID := HF.ConsEgress
						// we abuse Peerdelay and peerlink here to store an additional value for the AS
						// in which the segment crossover happens
						res.SingleDelays[IA] = ASDelay{
							Intradelay: gatherxoverlatency(oldSI, egIFID),
							Interdelay: SI.Latency.Egresslatency,
							Peerdelay:  oldSI.Latency.Egresslatency,
						}
						res.Links[IA] = ASLink{
							InterLinkType: SI.Linktype.EgressLinkType,
							PeerLinkType:  oldSI.Linktype.EgressLinkType,
						}
						res.Singlebw[IA] = ASBandwidth{
							IntraBW: gatherxoverbw(oldSI, egIFID),
							InterBW: SI.Bandwidth.EgressBW,
						}
						res.SingleHops[IA] = ASHops{
							Hops: gatherxoverhops(oldSI, egIFID),
						}
						res.Geo[IA] = ASGeo{
							locations: gathergeo(oldSI),
						}
						res.Notes[IA] = ASnote{
							Note: SI.Note,
						}
						UpOver = false
					}
					// If we're in the AS where we cross over from a core to a down segment
					// (i.e. Downover is set), fill pathmetadata using current ASEntry with
					// DownoverIFID as ingress interface
					if DownOver{
						IA := asEntry.IA()
						res.SingleDelays[IA] = ASDelay{
							Intradelay: gatherxoverlatency(SI, DownOverifID),
							Interdelay: SI.Latency.Egresslatency,
							Peerdelay:  0,
						}
						res.Links[IA] = ASLink{
							InterLinkType: SI.Linktype.EgressLinkType,
						}
						res.Singlebw[IA] = ASBandwidth{
							IntraBW: gatherxoverbw(SI, DownOverifID),
							InterBW: SI.Bandwidth.EgressBW,
						}
						res.SingleHops[IA] = ASHops{
							Hops: gatherxoverhops(SI, DownOverifID),
						}
						res.Geo[IA] = ASGeo{
							locations: gathergeo(SI),
						}
						res.Notes[IA] = ASnote{
							Note: SI.Note,
						}
						DownOver = false
					}
					//if we're in the last entry of the up segment, do nothign except set the UpOver flag
					if !(solEdge.segment.Type == iscoreseg){
						UpOver = true
						UpOverEntry = asEntry
					}
				}
			}
		}
	}
	return &res
}

func gatherxoverlatency(SI *seg.StaticInfoExtn, inIFID common.IFIDType) uint16{
	for i:=0;i< len(SI.Latency.Childlatencies);i++{
		if (SI.Latency.Childlatencies[i].IfID==inIFID){
			return SI.Latency.Childlatencies[i].Intradelay
		}
	}
	return 0
}


func gatherpeeringlatencydata(SI *seg.StaticInfoExtn, inIFID common.IFIDType) (uint16, uint16){
	var intradelay, peeringdelay uint16
	for i:=0;i< len(SI.Latency.Peerlatencies);i++{
		if (SI.Latency.Peerlatencies[i].IfID==inIFID){
			intradelay = SI.Latency.Peerlatencies[i].IntraDelay
			peeringdelay = SI.Latency.Peerlatencies[i].Interdelay
		}
	}
	return intradelay, peeringdelay
}


func gatherpeeroverlink(SI *seg.StaticInfoExtn, inIFID common.IFIDType) uint16{
	for i:=0;i< len(SI.Linktype.Peerlinks);i++{
		if (SI.Linktype.Peerlinks[i].IfID == inIFID){
			return SI.Linktype.Peerlinks[i].LinkType
		}
	}
	return 0
}


func gatherxoverbw(SI *seg.StaticInfoExtn, inIFID common.IFIDType) uint32{
	for i:=0;i< len(SI.Bandwidth.Bandwidths);i++ {
		if (SI.Bandwidth.Bandwidths[i].IfID == inIFID) {
			return SI.Bandwidth.Bandwidths[i].BW
		}
	}
	return 0
}

func gatherxoverhops(SI *seg.StaticInfoExtn, inIFID common.IFIDType) uint8 {
	for i := 0; i < len(SI.Hops.InterfaceHops); i++ {
		if (SI.Hops.InterfaceHops[i].IfID == inIFID) {
			return SI.Hops.InterfaceHops[i].Hops
		}
	}
	return 0
}

func gathergeo(SI *seg.StaticInfoExtn) ([]GeoLoc){
	var loc []GeoLoc
	for _, geocluster := range SI.Geo.Locations{
		loc = append(loc, GeoLoc{
			Latitude:  geocluster.GPSData.Latitude,
			Longitude: geocluster.GPSData.Longitude,
			CivAddr:   geocluster.GPSData.Address,
		})
	}
	return loc
}

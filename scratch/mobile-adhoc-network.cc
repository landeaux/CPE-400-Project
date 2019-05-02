/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
//
// This program configures a grid (default 5x5) of nodes on an
// 802.11b physical layer, with
// 802.11b NICs in adhoc mode, and by default, sends one packet of 1000
// (application) bytes to node 1.
//
// The default layout is like this, on a 2-D grid.
//
// n20  n21  n22  n23  n24
// n15  n16  n17  n18  n19
// n10  n11  n12  n13  n14
// n5   n6   n7   n8   n9
// n0   n1   n2   n3   n4
//
// the layout is affected by the parameters given to GridPositionAllocator;
// by default, GridWidth is 5 and numNodes is 25..
//
// There are a number of command-line options available to control
// the default behavior.  The list of available command-line options
// can be listed with the following command:
// ./waf --run "mobile-adhoc-network --help"
//
// Note that all ns-3 attributes (not just the ones exposed in the below
// script) can be changed at command line; see the ns-3 documentation.
//
// The source node and sink node can be changed like this:
//
// ./waf --run "wifi-simple-adhoc --sourceNode=20 --sinkNode=10"
//
// This script can also be helpful to put the Wifi layer into verbose
// logging mode; this command will turn on all wifi logging:
//
// ./waf --run "mobile-adhoc-network --verbose=1"
//
// By default, trace file writing is off-- to enable it, try:
// ./waf --run "mobile-adhoc-network --tracing=1"
//
// When you are done tracing, you will notice many pcap trace files
// in your directory.  If you have tcpdump installed, you can try this:
//
// tcpdump -r mobile-adhoc-network-0-0.pcap -nn -tt
//

#include "ns3/core-module.h"
#include "ns3/command-line.h"
#include "ns3/config.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"
#include "ns3/string.h"
#include "ns3/log.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/mobility-helper.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/ipv4-interface-address.h"
#include "ns3/yans-wifi-channel.h"
#include "ns3/mobility-model.h"
#include "ns3/olsr-helper.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/ipv4-list-routing-helper.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/netanim-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("WifiSimpleAdhocGrid");

//globals cuz MakeCallback is dumb :'(
uint32_t NUMBER_OF_NODES = 0;
std::ofstream HOPS_FILE;

void GetPacketHops(Ptr<Packet const> pkt, uint8_t& numHops, uint8_t initialTTL = 255) {
  Header* header = new Ipv4Header;
  pkt->PeekHeader(*header);
  //header->Print(std::cout);
  //std::cout << std::endl;
  uint8_t ttl = ((Ipv4Header*) header)->GetTtl();
  //NS_LOG_UNCOND((int) ttl);
  numHops = initialTTL - ttl;
}

static void LogHops(Ptr<Packet const> pkt, uint32_t numNodes, std::ofstream& out) {
  uint8_t hops;
  GetPacketHops(pkt, hops);
  out << numNodes << '\t' << (int) hops << std::endl;

}

void ReceivePacket (Ptr<Socket> socket)
{
  Ptr<Packet> pkt = socket->Recv();
  while (pkt != NULL) {
      NS_LOG_UNCOND ("Received one packet!");
      pkt = socket->Recv();
    }
}

void Ipv4L3ProtocolRxTxSink (Ptr<Packet const> pkt, Ptr<Ipv4> ipv4, uint32_t interface) {
  Ipv4Address addr = ipv4->GetAddress(interface, 0).GetLocal();
  Header* header = new Ipv4Header;
  pkt->PeekHeader(*header);
  if (((Ipv4Header*) header)->GetDestination() == addr) {
    LogHops(pkt, NUMBER_OF_NODES, HOPS_FILE);
  }
}

static void GenerateTraffic (Ptr<Socket> socket, uint32_t pktSize,
                             uint32_t pktCount, Time pktInterval )
{
  if (pktCount > 0)
    {
      socket->Send (Create<Packet> (pktSize));
      Simulator::Schedule (pktInterval, &GenerateTraffic,
                           socket, pktSize, pktCount - 1, pktInterval);
    }
  else
    {
      socket->Close ();
    }
}


int main (int argc, char *argv[])
{
  std::string phyMode ("DsssRate1Mbps");

  int id = 0;
  uint32_t packetSize = 1000; // bytes
  uint32_t numPackets = 1;
  uint32_t numNodes = 25;  // by default, 5x5
  uint32_t sinkNode = 0;
  uint32_t sourceNode = (uint32_t) -1;
  double interval = 1.0; // seconds
  bool verbose = false;
  bool tracing = false;
  uint32_t distance = 5;
  std::string hopsFileName = "";

  CommandLine cmd;
  cmd.AddValue ("id", "Experiment ID, to customize output file [0]", id);
  cmd.AddValue ("phyMode", "Wifi Phy mode", phyMode);
  cmd.AddValue ("packetSize", "size of application packet sent", packetSize);
  cmd.AddValue ("numPackets", "number of packets generated", numPackets);
  cmd.AddValue ("interval", "interval (seconds) between packets", interval);
  cmd.AddValue ("verbose", "turn on all WifiNetDevice log components", verbose);
  cmd.AddValue ("tracing", "turn on ascii and pcap tracing", tracing);
  cmd.AddValue ("numNodes", "number of nodes", numNodes);
  cmd.AddValue ("sinkNode", "Receiver node number", sinkNode);
  cmd.AddValue ("sourceNode", "Sender node number", sourceNode);
  cmd.AddValue ("distance", "Distance between nodes", distance);
  cmd.AddValue ("hopsFile", "File to append average hops per node", hopsFileName);
  cmd.Parse (argc, argv);
  // Convert to time object
  Time interPacketInterval = Seconds (interval);

  // Fix non-unicast data rate to be the same as that of unicast
  Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode",
                      StringValue (phyMode));

  if (sourceNode == ((uint32_t) -1))
  {
    sourceNode = numNodes - 1;
  }
  NUMBER_OF_NODES = numNodes;

  //std::ofstream hopsFile = NULL;
  if (hopsFileName != "") {
    //hopsFile.open(hopsFileName.c_str(), std::ofstream::out | std::ofstream::app);
    HOPS_FILE.open(hopsFileName.c_str(), std::ofstream::out | std::ofstream::app);
  }

  NodeContainer nodes;
  nodes.Create (numNodes);

  // The below set of helpers will help us to put together the wifi NICs we want
  WifiHelper wifi;
  if (verbose)
    {
      wifi.EnableLogComponents ();  // Turn on all Wifi logging
    }

  YansWifiPhyHelper wifiPhy =  YansWifiPhyHelper::Default ();
  // set it to zero; otherwise, gain will be added
  wifiPhy.Set ("RxGain", DoubleValue (-10) );
  // ns-3 supports RadioTap and Prism tracing extensions for 802.11b
  wifiPhy.SetPcapDataLinkType (WifiPhyHelper::DLT_IEEE802_11_RADIO);

  YansWifiChannelHelper wifiChannel;
  wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
  wifiChannel.AddPropagationLoss ("ns3::FriisPropagationLossModel");
  wifiPhy.SetChannel (wifiChannel.Create ());

  // Add an upper mac and disable rate control
  WifiMacHelper wifiMac;
  wifi.SetStandard (WIFI_PHY_STANDARD_80211b);
  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                "DataMode", StringValue (phyMode),
                                "ControlMode", StringValue (phyMode));
  // Set it to adhoc mode
  wifiMac.SetType ("ns3::AdhocWifiMac");
  NetDeviceContainer devices = wifi.Install (wifiPhy, wifiMac, nodes);

  MobilityHelper mobility;
  mobility.SetPositionAllocator ("ns3::GridPositionAllocator",
                                 "MinX", DoubleValue (2.0 * distance),
                                 "MinY", DoubleValue (2.0 * distance),
                                 "DeltaX", DoubleValue (distance),
                                 "DeltaY", DoubleValue (distance),
                                 "GridWidth", UintegerValue (5),
                                 "LayoutType", StringValue ("RowFirst"));

  // double speed = std::max((int) (distance / 3.0), 1);
  std::string val("ns3::ConstantRandomVariable[Constant=" + std::to_string(distance) + "]");
  mobility.SetMobilityModel ("ns3::RandomWalk2dMobilityModel",
                             "Bounds", RectangleValue (Rectangle (0, distance * 2 * 5, 0, distance * std::max((int) std::ceil(numNodes / 5), 1) * 2)),
                             "Speed", StringValue (val));
  
  //UintegerValue (std::max((int) (distance / 5.0), 1))

  mobility.Install (nodes);

  // Enable OLSR
  OlsrHelper olsr;
  Ipv4StaticRoutingHelper staticRouting;

  Ipv4ListRoutingHelper list;
  list.Add (staticRouting, 0);
  list.Add (olsr, 10);

  InternetStackHelper internet;
  internet.SetRoutingHelper (list); // has effect on the next Install ()
  internet.Install (nodes);

  Ipv4AddressHelper ipv4;
  NS_LOG_INFO ("Assign IP Addresses.");
  ipv4.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i = ipv4.Assign (devices);

  TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
  Ptr<Socket> recvSink = Socket::CreateSocket (nodes.Get (sinkNode), tid);
  InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), 80);
  recvSink->Bind (local);
  recvSink->SetRecvCallback (MakeCallback (&ReceivePacket));
  
  Config::ConnectWithoutContext("NodeList/*/$ns3::Ipv4L3Protocol/Rx", MakeCallback(Ipv4L3ProtocolRxTxSink));
  Ptr<Socket> source = Socket::CreateSocket (nodes.Get (sourceNode), tid);
  InetSocketAddress remote = InetSocketAddress (i.GetAddress (sinkNode, 0), 80);
  source->Connect (remote);

  if (tracing == true)
    {
      AsciiTraceHelper ascii;
      wifiPhy.EnableAsciiAll (ascii.CreateFileStream ("mobile-adhoc-network.tr"));
      wifiPhy.EnablePcap ("mobile-adhoc-network", devices);
      // Trace routing tables
      Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper> ("mobile-adhoc-network.routes", std::ios::out);
      olsr.PrintRoutingTableAllEvery (Seconds (2), routingStream);
      Ptr<OutputStreamWrapper> neighborStream = Create<OutputStreamWrapper> ("mobile-adhoc-network.neighbors", std::ios::out);
      olsr.PrintNeighborCacheAllEvery (Seconds (2), neighborStream);

      // To do-- enable an IP-level trace that shows forwarding events only
    }

  // Give OLSR time to converge-- 30 seconds perhaps
  Simulator::Schedule (Seconds (30.0), &GenerateTraffic,
                       source, packetSize, numPackets, interPacketInterval);

  // Output what we are doing
  NS_LOG_UNCOND ("Testing from node " << sourceNode << " to " << sinkNode);

  std::string animFilename = "mobile-adhoc-network-anim_" + std::to_string(id) + ".xml";
  AnimationInterface anim (animFilename);

  for (uint32_t i = 0; i < numNodes; i++)
  {
    anim.UpdateNodeSize (i, (distance / 5.0), (distance / 5.0));
  }

  anim.UpdateNodeDescription (nodes.Get (sourceNode), "Source");
  anim.UpdateNodeColor (nodes.Get (sourceNode), 0, 255, 0);
  anim.UpdateNodeDescription (nodes.Get (sinkNode), "Sink");
  anim.UpdateNodeColor (nodes.Get (sinkNode), 0, 0, 255);

  Simulator::Stop (Seconds (33.0));
  Simulator::Run ();
  Simulator::Destroy ();

  return 0;
}


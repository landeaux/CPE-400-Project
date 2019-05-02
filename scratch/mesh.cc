/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2008,2009 IITP RAS
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Kirill Andreev <andreev@iitp.ru>
 *
 *
 * By default this script creates m_xSize * m_ySize square grid topology with
 * IEEE802.11s stack installed at each node with peering management
 * and HWMP protocol.
 * The side of the square cell is defined by m_step parameter.
 * When topology is created, UDP ping is installed to opposite corners
 * by diagonals. packet size of the UDP ping and interval between two
 * successive packets is configurable.
 * 
 *  m_xSize * step
 *  |<--------->|
 *   step
 *  |<--->|
 *  * --- * --- * <---Ping sink  _
 *  | \   |   / |                ^
 *  |   \ | /   |                |
 *  * --- * --- * m_ySize * step |
 *  |   / | \   |                |
 *  | /   |   \ |                |
 *  * --- * --- *                _
 *  ^ Ping source
 *
 *  See also MeshTest::Configure to read more about configurable
 *  parameters.
 */

#include <iostream>
#include <sstream>
#include <fstream>
#include <map>
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/applications-module.h"
#include "ns3/mesh-module.h"
#include "ns3/mobility-module.h"
#include "ns3/mesh-helper.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/netanim-module.h"
#include "ns3/flow-monitor.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/ipv4-flow-classifier.h"
#include "ns3/csma-module.h"
#include "ns3/olsr-module.h"
#include <sys/stat.h> // fileExists

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("TestMeshScript");

// Function: fileExists
// Credit: https://stackoverflow.com/a/6296808
/**
    Check if a file exists
@param[in] filename - the name of the file to check

@return    true if the file exists, else false

*/
bool fileExists(const std::string& filename)
{
    struct stat buf;
    if (stat(filename.c_str(), &buf) != -1)
    {
        return true;
    }
    return false;
}

/// Callback function for every time a packet is received (used to count hops)
std::ofstream HOPS_FILE;
uint32_t NUM_NODES;
void Ipv4L4ProtocolRxTxSink(Ptr<Packet const> pkt, Ptr<Ipv4> ipv4, uint32_t interface) {
  std::cout << "Packet received" << std::endl;
  Ipv4Address addr = ipv4->GetAddress(interface, 0).GetLocal();
  Header* header = new Ipv4Header;
  pkt->PeekHeader(*header);
  if (((Ipv4Header*) header)->GetDestination() == addr) {//If the packet received is at its destination
    uint8_t defaultTTL = 255;//set via configuration in CreateNodes
    uint8_t ttl = ((Ipv4Header*) header)->GetTtl();
    uint8_t numHops = defaultTTL - ttl;
    HOPS_FILE << NUM_NODES << '\t' << (int) numHops << std::endl;
    NS_LOG_DEBUG(std::to_string(NUM_NODES) << "\t" << std::to_string((int) numHops));
  }
}

/*
void Ipv6L3ProtocolRxTxSink(Ptr<Packet const> pkt, Ptr<Ipv6> ipv6, uint32_t interface) {
  std::cout << "Packet received" << std::endl;
  Ipv6Address addr = ipv6->GetAddress(interface, 0).GetAddress();
  Header* header = new Ipv6Header;
  pkt->PeekHeader(*header);
  if (((Ipv6Header*) header)->GetDestinationAddress() == addr) {//If the packet received is at its destination
    uint8_t defaultTTL = 255;//set via configuration in CreateNodes
    uint8_t ttl = ((Ipv6Header*) header)->GetTtl();
    uint8_t numHops = defaultTTL - ttl;
    HOPS_FILE << NUM_NODES << '\t' << (int) numHops << std::endl;
    NS_LOG_DEBUG(std::to_string(NUM_NODES) << "\t" << std::to_string((int) numHops));
  }
}
*/
/// Callback for receiving a ping
void UdpReceived(Ptr<Packet const> pkt) {
  NS_LOG_DEBUG("Packet Received!");
  Header* header = new Ipv4Header;
  pkt->PeekHeader(*header);
  uint8_t defaultTTL = 255;//set via configuration in CreateNodes
  uint8_t ttl = ((Ipv4Header*) header)->GetTtl();
  uint8_t numHops = defaultTTL - ttl;
  HOPS_FILE << NUM_NODES << '\t' << (int) numHops << std::endl;
  NS_LOG_DEBUG(std::to_string(NUM_NODES) << "\t" << std::to_string((int) numHops));
}

/// Generate packets for analysis
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

/// Callback to receive the packets
void ReceivePacket (Ptr<Socket> socket)
{
  Ptr<Packet> pkt = socket->Recv();
  while (pkt != NULL) {
      //NS_LOG_UNCOND ("Received one packet!");
      pkt = socket->Recv();
    }
}

/**
 * \ingroup mesh
 * \brief MeshTest class
 */
class MeshTest
{
public:
  /// Init test
  MeshTest ();
  /**
   * Configure test from command line arguments
   *
   * \param argc command line argument count
   * \param argv command line arguments
   */
  void Configure (int argc, char ** argv);
  /**
   * Run test
   * \returns the test status
   */
  int Run ();
private:
  int         m_id; ///< Experiment ID
  int         m_xSize; ///< X size
  int         m_ySize; ///< Y size
  int         m_numNodes; ///< total number of nodes
  double      m_step; ///< step
  double      m_randomStart; ///< random start
  double      m_totalTime; ///< total time
  double      m_packetInterval; ///< packet interval
  uint16_t    m_packetSize; ///< packet size
  uint32_t    m_nIfaces; ///< number interfaces
  bool        m_chan; ///< channel
  bool        m_pcap; ///< PCAP
  bool        m_ascii; ///< ASCII
  std::string m_stack; ///< stack
  std::string m_root; ///< root
  std::string m_hopsFileName; ///< Name of the file to hold hops count
  /// List of network nodes
  NodeContainer nodes;
  /// List of all mesh point devices
  NetDeviceContainer meshDevices;
  /// Addresses of interfaces:
  Ipv4InterfaceContainer interfaces;
  /// MeshHelper. Report is not static methods
  MeshHelper mesh;

  ApplicationContainer serverApps;

  ApplicationContainer clientApps;
private:
  /// Create nodes and setup their mobility
  void CreateNodes ();
  /// Install internet m_stack on nodes
  void InstallInternetStack ();
  /// Install applications
  void InstallApplication ();
  /// Print mesh devices diagnostics
  void Report ();
};
MeshTest::MeshTest () :
  m_id (0),
  m_xSize (3),
  m_ySize (3),
  m_step (10.0),
  m_randomStart (0.1),
  m_totalTime (100.0),
  m_packetInterval (0.1),
  m_packetSize (1024),
  m_nIfaces (1),
  m_chan (true),
  m_pcap (false),
  m_ascii (false),
  m_stack ("ns3::Dot11sStack"),
  m_root ("ff:ff:ff:ff:ff:ff"),
  m_hopsFileName("hopsFile")
{
}
void
MeshTest::Configure (int argc, char *argv[])
{
  CommandLine cmd;
  cmd.AddValue ("id", "Experiment ID, to customize output file", m_id);
  cmd.AddValue ("x-size", "Number of nodes in a row grid", m_xSize);
  cmd.AddValue ("y-size", "Number of rows in a grid", m_ySize);
  cmd.AddValue ("step",   "Size of edge in our grid (meters)", m_step);
  // Avoid starting all mesh nodes at the same time (beacons may collide)
  cmd.AddValue ("start",  "Maximum random start delay for beacon jitter (sec)", m_randomStart);
  cmd.AddValue ("time",  "Simulation time (sec)", m_totalTime);
  cmd.AddValue ("packet-interval",  "Interval between packets in UDP ping (sec)", m_packetInterval);
  cmd.AddValue ("packet-size",  "Size of packets in UDP ping (bytes)", m_packetSize);
  cmd.AddValue ("interfaces", "Number of radio interfaces used by each mesh point", m_nIfaces);
  cmd.AddValue ("channels",   "Use different frequency channels for different interfaces", m_chan);
  cmd.AddValue ("pcap",   "Enable PCAP traces on interfaces", m_pcap);
  cmd.AddValue ("ascii",   "Enable Ascii traces on interfaces", m_ascii);
  cmd.AddValue ("stack",  "Type of protocol stack. ns3::Dot11sStack by default", m_stack);
  cmd.AddValue ("root", "Mac address of root mesh point in HWMP", m_root);
  cmd.AddValue ("hopsFile", "The file to append the number of hops per packet", m_hopsFileName);
  cmd.Parse (argc, argv);

  m_numNodes = m_xSize * m_ySize;
  NUM_NODES = m_numNodes;
 
  NS_LOG_DEBUG ("Grid:" << m_xSize << "*" << m_ySize);
  NS_LOG_DEBUG ("Simulation time: " << m_totalTime << " s");
  if (m_ascii)
    {
      PacketMetadata::Enable ();
    }


}
void
MeshTest::CreateNodes ()
{ 
  /*
   * Create m_ySize*m_xSize stations to form a grid topology
   */
  nodes.Create (m_numNodes);
  // Configure YansWifiChannel
  YansWifiPhyHelper wifiPhy = YansWifiPhyHelper::Default ();
  YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default ();
  wifiPhy.SetChannel (wifiChannel.Create ());
  /*
   * Create mesh helper and set stack installer to it
   * Stack installer creates all needed protocols and install them to
   * mesh point device
   */
  mesh = MeshHelper::Default ();
  if (!Mac48Address (m_root.c_str ()).IsBroadcast ())
    {
      mesh.SetStackInstaller (m_stack, "Root", Mac48AddressValue (Mac48Address (m_root.c_str ())));
    }
  else
    {
      //If root is not set, we do not use "Root" attribute, because it
      //is specified only for 11s
      mesh.SetStackInstaller (m_stack);
    }
  if (m_chan)
    {
      mesh.SetSpreadInterfaceChannels (MeshHelper::SPREAD_CHANNELS);
    }
  else
    {
      mesh.SetSpreadInterfaceChannels (MeshHelper::ZERO_CHANNEL);
    }
  mesh.SetMacType ("RandomStart", TimeValue (Seconds (m_randomStart)));
  // Set number of interfaces - default is single-interface mesh point
  mesh.SetNumberOfInterfaces (m_nIfaces);
  // Install protocols and return container if MeshPointDevices
  meshDevices = mesh.Install (wifiPhy, nodes);

  // Setup mobility - random walk grid topology
  MobilityHelper mobility;
  mobility.SetPositionAllocator ("ns3::GridPositionAllocator",
                                 "MinX", DoubleValue (m_step),
                                 "MinY", DoubleValue (m_step),
                                 "DeltaX", DoubleValue (m_step),
                                 "DeltaY", DoubleValue (m_step),
                                 "GridWidth", UintegerValue (m_xSize),
                                 "LayoutType", StringValue ("RowFirst"));
  std::string speed("ns3::ConstantRandomVariable[Constant=" + std::to_string(m_step) + "]");
  double xMin = 0;
  double xMax = m_step * 2 * m_xSize;
  double yMin = 0;
  double yMax = m_step * 2 * (double)m_ySize;
  Rectangle bounds = Rectangle (xMin, xMax, yMin, yMax);
  mobility.SetMobilityModel ("ns3::RandomWalk2dMobilityModel",
                             "Bounds", RectangleValue (bounds),
                             "Speed", StringValue (speed));
  mobility.Install (nodes);

  if (m_pcap)
    wifiPhy.EnablePcapAll (std::string ("mp-"));
  if (m_ascii)
    {
      AsciiTraceHelper ascii;
      wifiPhy.EnableAsciiAll (ascii.CreateFileStream ("mesh.tr"));
    }
}
void
MeshTest::InstallInternetStack ()
{
  /*
  OlsrHelper olsr;
  Ipv4StaticRoutingHelper staticRouting;
  Ipv4ListRoutingHelper list;
  list.Add (staticRouting, 0);
  list.Add (olsr, 10);
  */

  InternetStackHelper internetStack;
  //internetStack.SetRoutingHelper(list);
  internetStack.Install (nodes);
  Ipv4AddressHelper address;
  address.SetBase ("10.1.1.0", "255.255.255.0");
  interfaces = address.Assign (meshDevices);
  
  
  CsmaHelper csma;
  NetDeviceContainer ndc = csma.Install(nodes);
  Ipv6AddressHelper ipv6;
  ipv6.SetBase (Ipv6Address ("2001:1::"), Ipv6Prefix (64));
  Ipv6InterfaceContainer ic = ipv6.Assign (ndc);
  ic.SetForwarding (1, true);
  ic.SetDefaultRouteInAllNodes (1); 
  
}
void
MeshTest::InstallApplication ()
{
  Config::Connect("/NodeList/0/ApplicationList/1/$ns3::UdpEchoServer/Rx", MakeCallback(&UdpReceived));
  UdpEchoServerHelper echoServer (9);
  serverApps = echoServer.Install (nodes.Get (0));
  serverApps.Start (Seconds (0.0));
  serverApps.Stop (Seconds (m_totalTime));
  UdpEchoClientHelper echoClient (interfaces.GetAddress (0), 9);
  echoClient.SetAttribute ("MaxPackets", UintegerValue ((uint32_t)(m_totalTime*(1/m_packetInterval))));
  echoClient.SetAttribute ("Interval", TimeValue (Seconds (m_packetInterval)));
  echoClient.SetAttribute ("PacketSize", UintegerValue (m_packetSize));
  clientApps = echoClient.Install (nodes.Get (m_numNodes-1));
  clientApps.Start (Seconds (0.0));
  clientApps.Stop (Seconds (m_totalTime));
}
int
MeshTest::Run ()
{
  //Set Default TTL
  Config::SetDefault("ns3::Ipv4L3Protocol::DefaultTtl", UintegerValue(255));
  //Attach callback to IPv4 Packets on L3 for packet reception
  Config::ConnectWithoutContext("NodeList/*/$ns3::Ipv4L4Protocol/Rx", MakeCallback(&Ipv4L4ProtocolRxTxSink));
  //Config::ConnectWithoutContext("NodeList/*/$ns3::Ipv6L3Protocol/Rx", MakeCallback(&Ipv6L3ProtocolRxTxSink));
  //Open file to log number of hops for each UDP packet
  HOPS_FILE.open(m_hopsFileName.c_str(), std::ofstream::out | std::ofstream::app);

  CreateNodes ();
  InstallInternetStack ();
  InstallApplication ();
  Simulator::Schedule (Seconds (m_totalTime), &MeshTest::Report, this);
  Simulator::Stop (Seconds (m_totalTime));

  std::string animMeshFilename = "mobile-adhoc-network-anim-mesh_" + std::to_string(m_id) + ".xml";
  AnimationInterface anim (animMeshFilename);
  
  // Update Node Color for all nodes
  for (uint32_t i = 0; i < nodes.GetN (); i++)
    {
      anim.UpdateNodeColor (nodes.Get (i), 255, 0, 0);
    }

  // Update Node Color and Description for Sink and Source nodes
  anim.UpdateNodeDescription (nodes.Get (m_numNodes-1), "Source");
  anim.UpdateNodeColor (nodes.Get (m_numNodes-1), 0, 255, 0);
  anim.UpdateNodeDescription (nodes.Get (0), "Sink");
  anim.UpdateNodeColor (nodes.Get (0), 0, 0, 255);

  // Enable tracking of the Ipv4 routing table for all Nodes.
  std::string animMeshTraceFilename = "mobile-adhoc-network-anim-mesh-trace_" + std::to_string(m_id) + ".xml";
  anim.EnableIpv4RouteTracking (animMeshTraceFilename, Seconds (0), Seconds (5), Seconds(0.25));

  // Enable tracking of Wifi Mac and Phy Counters such as Tx, TxDrop, Rx, RxDrop.
  anim.EnableWifiMacCounters (Seconds (0), Seconds(10));
  anim.EnableWifiPhyCounters (Seconds (0), Seconds(10));

  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor = flowmon.InstallAll();

  /*
  // Set up sockets for sending and receiving packets
  TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
  Ptr<Socket> recvSink = Socket::CreateSocket (nodes.Get (0), tid);
  InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), 80);
  recvSink->Bind (local);
  recvSink->SetRecvCallback (MakeCallback (&ReceivePacket));
  
  Ptr<Socket> source = Socket::CreateSocket (nodes.Get (m_numNodes - 1), tid);
  InetSocketAddress remote = InetSocketAddress (interfaces.GetAddress (0, 0), 80);
  source->Connect (remote);

  //Schedule packets
  int numPackets = 1;
  Time interPacketInterval = Seconds(m_packetInterval);

  Simulator::Schedule (Seconds (m_totalTime / 3), &GenerateTraffic,
                       source, m_packetSize, numPackets, interPacketInterval);
  Simulator::Schedule (Seconds (2 * (m_totalTime / 3)), &GenerateTraffic,
                       source, m_packetSize, numPackets, interPacketInterval);
  Simulator::Schedule (Seconds (m_totalTime - 10), &GenerateTraffic,
                       source, m_packetSize, numPackets, interPacketInterval);
  */

  Simulator::Run ();

  monitor->CheckForLostPackets ();
  Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowmon.GetClassifier ());
  std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats ();

  uint32_t txPacketSum = 0;   // 15
  uint32_t rxPacketSum = 0;   // 10 
  uint32_t dropPacketSum = 0; // 15
  uint32_t lostPacketSum = 0; // 15
  uint32_t rxBytesSum = 0;    // 15
  double delaySum = 0;        // 0

  // std::ofstream ofs ("ResultGraph.plt", std::ofstream::out);

  // ofs << "set terminal png" << std::endl;
  // ofs << "set output 'ResultGraph.png'" << std::endl;
  // ofs << "set title ''" << std::endl;
  // ofs << "set xlabel 'Nodes'" << std::endl;
  // ofs << "set ylabel 'value'" << std::endl;
  // ofs << "plot" << " '-' title 'Packet Inter-arrival Time (ms)' with linespoints,"
  //               << " '-' title 'Jitter' with lines,"
  //               << " '-' title 'Throughput' with lines,"
  //               << " '-' title 'Delay' with lines" << std::endl;
  // ofs << "1 " << 0 << std::endl;
  // ofs << (m_numNodes) << " " << Seconds (m_packetInterval) / (1e8) << std::endl;
  // ofs << "e" << std::endl;
  // ofs << "1 " << 0 << std::endl;
  // ofs << (m_numNodes) << " " << avgJitter << std::endl;
  // ofs << "e" << std::endl;
  // ofs << "1 " << 0 << std::endl;
  // ofs << (m_numNodes) << " " << avgThroughput << std::endl;
  // ofs << "e" << std::endl;
  // ofs << "1 " << 0 << std::endl;
  // ofs << (m_numNodes) << " " << avgDelay << std::endl;
  // ofs << "e" << std::endl;

  std::ofstream ofs;

  if (!fileExists("results.dat"))
    {
      ofs.open ("results.dat");
      ofs << "experimentID numNodes nodeID txPackets rxPackets lostPackets dropPackets delay rxBytes" << std::endl;
    }
  else 
    {
      ofs.open ("results.dat", std::ofstream::app);
    }

  //uint16_t packetHopsSum = 0;
  int count = 0;
  for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator iter = stats.begin (); iter != stats.end (); ++iter)
    {
      count++;
      uint32_t nodeID      = iter->first;
      uint32_t txPackets   = iter->second.txPackets;
      uint32_t rxPackets   = iter->second.rxPackets;
      uint32_t lostPackets = iter->second.lostPackets;
      uint32_t dropPackets = iter->second.packetsDropped.size ();
      double   delay       = iter->second.delaySum.GetSeconds ();
      uint32_t rxBytes     = iter->second.rxBytes;
      //uint8_t packetHops   = iter->second.timesForwarded;

      txPacketSum   += txPackets;
      rxPacketSum   += rxPackets;
      lostPacketSum += lostPackets;
      dropPacketSum += dropPackets;
      delaySum      += delay;
      rxBytesSum    += rxBytes;
      //packetHopsSum  += packetHops;

      ofs << m_id        << " "
          << m_numNodes  << " "
          << nodeID      << " "
          << txPackets   << " "
          << rxPackets   << " "
          << lostPackets << " "
          << dropPackets << " "
          << delay       << " "
          << rxBytes     << "\n";
          //<< packetHops  << "\n";
    }

  ofs.close();

  double avgPDR = ((rxPacketSum * 100) / txPacketSum); // PDR = Packet Delivery Ratio
  double avgJitter = ((lostPacketSum * 100) / txPacketSum);
  double avgThroughput = ((rxBytesSum * 8.0) / m_totalTime) / 1024 / 4;
  double avgDelay = (delaySum / rxPacketSum) * 1000;
  //uint8_t avgPacketHops =  std::ceil((double)packetHopsSum / (double)count);

  if (!fileExists("averages.dat"))
    {
      ofs.open ("averages.dat");
      ofs << "experimentID numNodes nodeID txPackets rxPackets lostPackets dropPackets delay rxBytes" << std::endl;
    }
  else 
    {
      ofs.open ("averages.dat", std::ofstream::app);
    }

  ofs << m_id          << " "
      << avgPDR        << " "
      << avgJitter     << " "
      << avgThroughput << " "
      << avgDelay      << "\n";

  NS_LOG_UNCOND ("\ntxPacketSum: " << txPacketSum   << " ");
  NS_LOG_UNCOND ("rxPacketSum: "   << rxPacketSum   << " ");
  NS_LOG_UNCOND ("lostPacketSum: " << lostPacketSum << " ");
  NS_LOG_UNCOND ("dropPacketSum: " << dropPacketSum << " ");
  NS_LOG_UNCOND ("delaySum: "      << delaySum      << " ms");
  NS_LOG_UNCOND ("rxBytesSum: "    << rxBytesSum    << " B\n");
  //NS_LOG_UNCOND ("packetHopsSum: " << (int) packetHopsSum << "\n");

  NS_LOG_UNCOND ("Average PDR: "        << avgPDR        << " ");
  NS_LOG_UNCOND ("Average Jitter: "     << avgJitter     << " ");
  NS_LOG_UNCOND ("Average Throughput: " << avgThroughput << " Mbps");
  NS_LOG_UNCOND ("Average Delay: "      << avgDelay      << " ms");
  //NS_LOG_UNCOND ("Average Hops Per Packet: " << (int) avgPacketHops << "\n");

  ofs.close();
  HOPS_FILE.close();
  Simulator::Destroy ();
  
  return 0;
}
void
MeshTest::Report ()
{
  unsigned n (0);
  for (NetDeviceContainer::Iterator i = meshDevices.Begin (); i != meshDevices.End (); ++i, ++n)
    {
      std::ostringstream os;
      os << "mp-report-" << std::to_string(m_id) << "-" << n << ".xml";
      std::cerr << "Printing mesh point device #" << n << " diagnostics to " << os.str () << "\n";
      std::ofstream of;
      of.open (os.str ().c_str ());
      if (!of.is_open ())
        {
          std::cerr << "Error: Can't open file " << os.str () << "\n";
          return;
        }
      mesh.Report (*i, of);
      of.close ();
    }
}
int
main (int argc, char *argv[])
{
  MeshTest t; 
  t.Configure (argc, argv);
  return t.Run ();
}

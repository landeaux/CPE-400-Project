#include "ns3/core-module.h"           // core simulator functions
#include "ns3/network-module.h"        // basic networking classes: nodes, devices, etc
#include "ns3/point-to-point-module.h" // point-to-point functions
#include "ns3/internet-module.h"       // internet stack logic
#include "ns3/applications-module.h"   // application layer: generates/consumes data

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("OurFirstSimulation");

int main (int argc, char *argv[])
{
    NS_LOG_UNCOND("OurFirstSimulation");

    int m_id = 0;
    double m_time = 100.0;
    uint16_t m_sinkPort = 8080;

    // Parse command line arguments. Variables must be declared beforehand!
    CommandLine cmd;
    cmd.AddValue(
        "id", 
        "Experiment ID, to customize output file [0]", 
        m_id
    );
    cmd.AddValue(
        "time", 
        "Simulation time [100 s]", 
        m_time
    );
    cmd.AddValue(
        "sinkPort", 
        "Port the server will be listening to [8080]", 
        m_sinkPort
    );
    cmd.Parse(argc, argv);

    // Create the nodes
    NodeContainer nodes;
    nodes.Create(2);

    // Create p2p helper with some configuration
    PointToPointHelper pointToPoint;
    pointToPoint.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
    pointToPoint.SetChannelAttribute("Delay", StringValue("2ms"));

    // Install devices on the nodes
    NetDeviceContainer devices;
    devices = pointToPoint.Install(nodes);

    // Error model. This is a smart-pointer! Instead of dealing with *'s and &'s, ns-3 uses Ptr<>
    Ptr<RateErrorModel> em = CreateObject<RateErrorModel>();
    em->SetAttribute("ErrorRate", DoubleValue(0.00001));
    devices.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(em));

    // TCP/IP Stack
    InternetStackHelper stack;
    stack.Install(nodes);
    Ipv4AddressHelper addresses;
    addresses.SetBase("10.1.1.0", "255.255.255.0");
    // keeps track of device/address pairs
    Ipv4InterfaceContainer interfaces = addresses.Assign(devices);

    // Install server application to consume data
    PacketSinkHelper packetSinkHelper(
        "ns3::TcpSocketFactory", 
        InetSocketAddress(Ipv4Address::GetAny(), m_sinkPort)
    );
    ApplicationContainer sinkApps = packetSinkHelper.Install(nodes.Get(1));
    sinkApps.Start(Seconds(0.));
    sinkApps.Stop(Seconds(100.));

    // Source application. Destination = address of node 1
    BulkSendHelper bulkSendHelper(
        "ns3::TcpSocketFactory", 
        InetSocketAddress(interfaces.GetAddress(1), m_sinkPort)
    );
    bulkSendHelper.SetAttribute("MaxBytes", UintegerValue(1000000000));
    ApplicationContainer bulkApps = bulkSendHelper.Install(nodes.Get(0));
    bulkApps.Start(Seconds(1.));
    bulkApps.Stop(Seconds(m_time - 1));

    // Run the simulation!
    Simulator::Stop(Seconds(m_time));
    Simulator::Run();
    Simulator::Destroy();
}
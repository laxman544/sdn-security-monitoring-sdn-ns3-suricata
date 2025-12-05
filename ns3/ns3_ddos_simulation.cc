// ns3_ddos_simulation.cc
// Simple SDN-like topology with UDP flood DDoS traffic
// Author: Pinnaka Khantirava Venkat Laxman Kumar

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("SdnDdosSimulation");

int main(int argc, char *argv[])
{
    double simTime = 20.0;        // total simulation time (seconds)
    double attackStart = 5.0;     // attack start time (seconds)
    double attackStop  = 15.0;    // attack stop time (seconds);
    std::string dataRate = "10Mbps";
    uint32_t packetSize = 512;

    CommandLine cmd;
    cmd.AddValue("simTime", "Simulation time in seconds", simTime);
    cmd.Parse(argc, argv);

    // Create nodes:
    // 0: attacker1, 1: attacker2, 2: background, 3: victim, 4: router
    NodeContainer allNodes;
    allNodes.Create(5);

    Ptr<Node> attacker1 = allNodes.Get(0);
    Ptr<Node> attacker2 = allNodes.Get(1);
    Ptr<Node> background = allNodes.Get(2);
    Ptr<Node> victim = allNodes.Get(3);
    Ptr<Node> router = allNodes.Get(4);

    InternetStackHelper stack;
    stack.Install(allNodes);

    // Point-to-point links from each host to router
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("5ms"));

    NetDeviceContainer d0r = p2p.Install(attacker1, router);
    NetDeviceContainer d1r = p2p.Install(attacker2, router);
    NetDeviceContainer d2r = p2p.Install(background, router);
    NetDeviceContainer d3r = p2p.Install(victim, router);

    // Assign IP addresses
    Ipv4AddressHelper address;
    address.SetBase("10.0.1.0", "255.255.255.0");
    Ipv4InterfaceContainer i0r = address.Assign(d0r);

    address.SetBase("10.0.2.0", "255.255.255.0");
    Ipv4InterfaceContainer i1r = address.Assign(d1r);

    address.SetBase("10.0.3.0", "255.255.255.0");
    Ipv4InterfaceContainer i2r = address.Assign(d2r);

    address.SetBase("10.0.4.0", "255.255.255.0");
    Ipv4InterfaceContainer i3r = address.Assign(d3r);

    Ipv4Address attacker1Ip = i0r.GetAddress(0);
    Ipv4Address attacker2Ip = i1r.GetAddress(0);
    Ipv4Address backgroundIp = i2r.GetAddress(0);
    Ipv4Address victimIp = i3r.GetAddress(0);

    NS_LOG_INFO("Attacker1: " << attacker1Ip);
    NS_LOG_INFO("Attacker2: " << attacker2Ip);
    NS_LOG_INFO("Background: " << backgroundIp);
    NS_LOG_INFO("Victim: " << victimIp);

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // UDP server on victim (port 5000)
    uint16_t port = 5000;
    UdpServerHelper udpServer(port);
    ApplicationContainer serverApps = udpServer.Install(victim);
    serverApps.Start(Seconds(0.0));
    serverApps.Stop(Seconds(simTime));

    // UDP flood from attackers
    OnOffHelper onoff("ns3::UdpSocketFactory",
                      InetSocketAddress(victimIp, port));
    onoff.SetConstantRate(DataRate(dataRate), packetSize);

    // Attacker 1
    onoff.SetAttribute("StartTime", TimeValue(Seconds(attackStart)));
    onoff.SetAttribute("StopTime", TimeValue(Seconds(attackStop)));
    ApplicationContainer a1App = onoff.Install(attacker1);

    // Attacker 2
    ApplicationContainer a2App = onoff.Install(attacker2);

    // Background low-rate UDP traffic
    OnOffHelper bgOnOff("ns3::UdpSocketFactory",
                        InetSocketAddress(victimIp, port));
    bgOnOff.SetConstantRate(DataRate("1Mbps"), packetSize);
    bgOnOff.SetAttribute("StartTime", TimeValue(Seconds(1.0)));
    bgOnOff.SetAttribute("StopTime", TimeValue(Seconds(simTime - 1.0)));
    ApplicationContainer bgApp = bgOnOff.Install(background);

    // Enable PCAP tracing
    p2p.EnablePcapAll("ns3_ddos", true);

    // FlowMonitor
    FlowMonitorHelper flowHelper;
    Ptr<FlowMonitor> monitor = flowHelper.InstallAll();

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    // Analyze flows
    monitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier =
        DynamicCast<Ipv4FlowClassifier>(flowHelper.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();

    double thresholdMbps = 2.0;
    std::cout << "=== Suspicious flows (throughput > "
              << thresholdMbps << " Mbps) ===" << std::endl;

    for (auto const &flow : stats)
    {
        FlowId id = flow.first;
        FlowMonitor::FlowStats st = flow.second;
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(id);

        double timeSec = (st.timeLastRxPacket.GetSeconds() -
                          st.timeFirstTxPacket.GetSeconds());
        if (timeSec <= 0) continue;

        double throughputMbps = (st.rxBytes * 8.0 / timeSec) / 1e6;

        if (throughputMbps > thresholdMbps)
        {
            std::cout << "Flow " << id << " "
                      << t.sourceAddress << " -> "
                      << t.destinationAddress
                      << "  Throughput: " << throughputMbps << " Mbps"
                      << std::endl;
        }
    }

    monitor->SerializeToXmlFile("flows.xml", true, true);

    Simulator::Destroy();
    return 0;
}

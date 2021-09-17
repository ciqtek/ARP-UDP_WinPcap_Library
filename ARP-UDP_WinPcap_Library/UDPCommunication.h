#ifndef CUDPCOMMUNICATION_H
#define CUDPCOMMUNICATION_H

#include <iostream>
#include <atomic>
#include <mutex>

#include "WinPcap/Include/pcap.h"

class CUDPCommunication
{
private:
	//以太网头部(14)
#pragma pack(1)
	struct EthernetHeader
	{
		unsigned char  TargetMacAddress[6];//目标MAC地址
		unsigned char  SourceMacAddress[6];//源MAC地址
		unsigned short TypesOf;//类型
	};
#pragma pack()

	//IP协议头结构(20)
#pragma pack(1)
	struct IpSeaderStructure
	{
		unsigned char  Version_HeadLength;//版本、头长度
		unsigned char  ServiceType;//服务类型
		unsigned short TotalLengthOfPacket;//封包总长度
		unsigned short PacketIdentification;//封包标识
		unsigned short FragmentOffsetAddress;//片断偏移地址
		unsigned char  SurvivalTime;//存活时间
		unsigned char  Protocol;//协议
		unsigned short Checksum;//校验和
		unsigned int   SourceIpAddress;//源IP地址
		unsigned int   TargetIpAddress;//目标IP地址
	};
#pragma pack()

	//UDP协议头结构(8)
#pragma pack(1)
	struct UdpHeaderStructure
	{
		unsigned short SourcePort;//源端口
		unsigned short DestinationPort;//目的端口
		unsigned short PacketLength;//封包长度
		unsigned short Checksum;//校验和
	};
#pragma pack()

public:
	CUDPCommunication();
	~CUDPCommunication();

public:
	bool Bind(std::string local_ip, std::string local_mac, std::string device_ip, std::string device_mac);
	int  Write(unsigned short src_port, unsigned short dest_port, const unsigned char* buffer, int len);
	int  Read(unsigned short dest_port, unsigned char* buffer, int size);
	bool Close();

private:
	bool Init(std::string& local_ip, std::string& local_mac, std::string& device_ip, std::string& device_mac);
	bool CreateNetMac(std::string mac, unsigned char* net_mac, int len);

private:
	unsigned char * CreateUDPPacket(unsigned char*, unsigned char*, unsigned int, unsigned int, 
		unsigned short, unsigned short, unsigned char*, unsigned int);

	unsigned short CalculateUDPChecksum(unsigned char* UserData, int UserDataLen, UINT SourceIP, UINT DestIP, 
		USHORT SourcePort, USHORT DestinationPort, UCHAR Protocol, unsigned char* FinalPacket);

	unsigned short CalculateIPChecksum(UINT TotalLen, UINT ID, UINT SourceIP, UINT DestIP, unsigned char* FinalPacket);

	unsigned short BytesTo16(unsigned char X, unsigned char Y);

private:
	pcap_t* m_pcap;

	/*存储网络数据 避免创建UDP包数据重复转换*/
	unsigned int m_local_ip;
	unsigned char m_local_mac[6];
	unsigned int m_device_ip;
	unsigned char m_device_mac[6];

	std::atomic<int> packet_flag = 0;

	std::atomic<bool> is_init_success;
	std::mutex read_mux;
	std::mutex write_mux;
};
#endif //CUDPCOMMUNICATION_H
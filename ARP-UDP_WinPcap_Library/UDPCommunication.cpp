#define MAX_SIZE 1024
#define WIN32

#include "UDPCommunication.h"
#include "net_helper/net_helper.h"
#include "winsock2.h"

#include <string>
#include <vector>

#define LIBPATH(p,f)   p##f
#ifdef _WIN64
#pragma comment(lib,LIBPATH(__FILE__,"/../WinPcap/Lib/x64/wpcap.lib"))
#else
#pragma comment(lib,LIBPATH(__FILE__,"/../WinPcap/Lib/wpcap.lib"))
#endif // _WIN64

#pragma comment(lib,"Ws2_32.lib")

CUDPCommunication::CUDPCommunication() :
	m_pcap(nullptr),
	is_init_success(false),
	m_local_ip(0),
	m_device_ip(0)
{
	memset(m_local_mac, 0, sizeof(m_local_mac));
	memset(m_device_mac, 0, sizeof(m_device_mac));
}

CUDPCommunication::~CUDPCommunication()
{
	Close();
	printf_s("exit ~CUDPCommunication()\n");
}

bool CUDPCommunication::Init(std::string& local_ip, std::string& local_mac, std::string& device_ip, std::string& device_mac)
{
	if (local_mac.size() != 17 || device_mac.size() != 17)
	{
		is_init_success = false;
		return false;
	}

	m_local_ip = 0;
	inet_pton(AF_INET, local_ip.c_str(), &m_local_ip);
	if (!m_local_ip)
	{
		is_init_success = false;
		return false;
	}
	m_device_ip = 0;
	inet_pton(AF_INET, device_ip.c_str(), &m_device_ip);
	if (!m_local_ip)
	{
		is_init_success = false;
		return false;
	}
	
	if (!CreateNetMac(local_mac, m_local_mac, 6))
	{
		is_init_success = false;
		return false;
	}

	if (!CreateNetMac(device_mac, m_device_mac, 6))
	{
		is_init_success = false;
		return false;
	}

	is_init_success = true;
	return true;
}

bool CUDPCommunication::CreateNetMac(std::string mac, unsigned char* net_mac,int len)
{
	if (len < 6 || !net_mac)
	{
		return false;
	}

	std::string bare_mac;
	for (std::string::iterator it = mac.begin(); it != mac.end(); ++it)
	{
		if (*it != '-')
		{
			bare_mac.push_back(*it);
		}
	}
	if (bare_mac.size() != 12)
	{
		bare_mac.clear();
		return false;
	}

	int pos = 0;
	unsigned char net_mac_temp[6];
	for (int i = 0; i < 12; i += 2)
	{
		std::string ch = bare_mac.substr(i, 2);
		try
		{
			unsigned char num = std::stoi(ch, nullptr, 16);
			net_mac_temp[pos] = num;
			++pos;
		}
		catch (const std::exception&)
		{
			return false;
		}
	}
	memcpy(net_mac, net_mac_temp, 6);
	return true;
}

bool CUDPCommunication::Bind(std::string local_ip, std::string local_mac, std::string device_ip, std::string device_mac)
{
	std::lock_guard<std::mutex> read_lck(read_mux);
	std::lock_guard<std::mutex> write_lck(write_mux);
	if (m_pcap)
	{
		is_init_success = false;

		pcap_close(m_pcap);
		m_pcap = nullptr;

		memset(m_local_mac, 0, sizeof(m_local_mac));
		memset(m_device_mac, 0, sizeof(m_device_mac));

		m_device_ip = 0;
		m_local_ip = 0;

		packet_flag = 0;
	}

	bool result = Init(local_ip, local_mac, device_ip, device_mac);
	if (!result)
	{
		return false;
	}

	using namespace arp_net;
	net_adapter_helper& helper = net_adapter_helper::get_instance();
	net_ada_list ada_list = helper.get_info_win();
	if (ada_list.size() <= 0)
	{
		return false;
	}

	char adaptor_name[1024] = { 0 };
	unsigned int netmask;
	for (auto it = ada_list.begin(); it != ada_list.end(); ++it)
	{
		for (auto ip_it = it->_ip.begin(); ip_it != it->_ip.end(); ++ip_it)
		{
			if (ip_it->_inet4 == local_ip && it->_mac == local_mac)
			{
				strcpy_s(adaptor_name, ("\\Device_\\NPF_" + it->_name).c_str());
				inet_pton(AF_INET, ip_it->_subnet_mask.c_str(), &netmask);
				break;
			}
		}
		if (strlen(adaptor_name))
		{
			break;
		}
	}

	if (!strlen(adaptor_name))
	{
		return false;
	}

	char error_buffer[PCAP_ERRBUF_SIZE] = { 0 };
	m_pcap = pcap_open_live(adaptor_name, 65535, 1, 10, error_buffer);
	if (!m_pcap)
	{
		return false;
	}

	bpf_program fcode;
	if (pcap_compile(m_pcap, &fcode, ("udp and src host " + device_ip).c_str(), 1, netmask) == 0)
	{
		pcap_setfilter(m_pcap, &fcode);
	}

	return true;
}

bool CUDPCommunication::Close()
{
	std::lock_guard<std::mutex> read_lck(read_mux);
	std::lock_guard<std::mutex> write_lck(write_mux);

	if (m_pcap)
	{
		is_init_success = false;

		pcap_close(m_pcap);
		m_pcap = nullptr;

		memset(m_local_mac, 0, sizeof(m_local_mac));
		memset(m_device_mac, 0, sizeof(m_device_mac));

		m_device_ip = 0;
		m_local_ip = 0;

		packet_flag = 0;
	}
	return true;
}

int CUDPCommunication::Write(unsigned short local_port, unsigned short device_port, const unsigned char* buffer, int len)
{
	std::lock_guard<std::mutex> write_lck(write_mux);

	if (!is_init_success || !m_pcap)
	{
		return -1;
	}

	unsigned char * send_data = CreateUDPPacket(m_local_mac, m_device_mac, m_local_ip, m_device_ip,
		local_port, device_port, (unsigned char*)buffer, len);
	if (!send_data)
	{
		return -1;
	}

	int ret = pcap_sendpacket(m_pcap, send_data, len + 42);//以太网/IP/UDP包头数据共计42字节
	
	if (send_data)
	{
		delete send_data;
	}

	return ret == 0 ? len : -1;
}

int CUDPCommunication::Read(unsigned short dest_port, unsigned char* buffer, int size)
{
	std::lock_guard<std::mutex> read_lck(read_mux);

	if (!is_init_success || !m_pcap)
	{
		return -1;
	}

	const u_char * pkt_data = nullptr;
	pcap_pkthdr* header = nullptr;

	int ret = pcap_next_ex(m_pcap, &header, &pkt_data);

	if (ret != 1 || header->caplen != header->len)
	{
		return -1;
	}

	IpSeaderStructure* ip = (IpSeaderStructure*)(pkt_data + sizeof(EthernetHeader));
	int ip_header_len = (ip->Version_HeadLength & 0xf) * 4;

	UdpHeaderStructure* udp = (UdpHeaderStructure*)((unsigned char*)ip + ip_header_len);
	if (ntohs(udp->DestinationPort) != dest_port)
	{
		return -1;
	}

	int data_len = ntohs(udp->PacketLength) - sizeof(UdpHeaderStructure);
	if (size < data_len)
	{
		return -1;
	}

	memcpy(buffer, (unsigned char*)udp + sizeof(UdpHeaderStructure), data_len);

	return data_len;
}

unsigned char * CUDPCommunication::CreateUDPPacket(unsigned char*  SourceMAC, unsigned char* DestinationMAC,
	unsigned int SourceIP, unsigned int DestIP, unsigned short SourcePort,
	unsigned short DestinationPort, unsigned char* UserData, unsigned int UserDataLen)
{
	unsigned char* FinalPacket = new unsigned char[UserDataLen + 42];
	/*以太网头部，14个字节*/
	memcpy(FinalPacket, DestinationMAC, 6);
	memcpy(FinalPacket + 6, SourceMAC, 6);
	memcpy(FinalPacket + 12, "\x08\x00", 2);


	/*IP头部,没有自定义数据部分,20个字节*/
	memcpy(FinalPacket + 14, "\x45", 1);//IP包头最长为60个字节，最短为20个字节
	memcpy(FinalPacket + 15, "\x00", 1);
	uint16_t ip_len = htons(UserDataLen + 20 + 8);
	memcpy(FinalPacket + 16, &ip_len, 2);//指的是数据部分+UDP头+IP头
	if (packet_flag > 0xFFFF)
	{
		packet_flag = 0;
	}
	uint16_t flag = htons(packet_flag++);
	memcpy(FinalPacket + 18, &flag, 2);
	memcpy(FinalPacket + 20, "\x00", 1);
	memcpy(FinalPacket + 21, "\x00", 1);
	memcpy(FinalPacket + 22, "\xFF", 1);
	memcpy(FinalPacket + 23, "\x11", 1);
	memcpy(FinalPacket + 24, "\x00\x00", 2);
	memcpy(FinalPacket + 26, &SourceIP, 4);
	memcpy(FinalPacket + 30, &DestIP, 4);

	/*UDP头部，8个字节*/
	uint16_t src_port = htons(SourcePort);
	memcpy(FinalPacket + 34, &src_port, 2);
	uint16_t dest_port = htons(DestinationPort);
	memcpy(FinalPacket + 36, &dest_port, 2);
	uint16_t udp_len = htons(UserDataLen + 8);
	memcpy(FinalPacket + 38, &udp_len, 2);

	/*数据部分 UserDataLen个字节*/
	memcpy(FinalPacket + 42, UserData, UserDataLen);
	
	unsigned short UDPChecksum = CalculateUDPChecksum(UserData, UserDataLen, SourceIP, DestIP, htons(SourcePort), htons(DestinationPort), 0x11, FinalPacket);
	memcpy(FinalPacket + 40, &UDPChecksum, 2);

	unsigned short IPChecksum = htons(CalculateIPChecksum(UserDataLen + 20 + 8, 0x1337, SourceIP, DestIP, FinalPacket));//IP头部首位校验和
	memcpy(FinalPacket + 24, &IPChecksum, 2);

	return FinalPacket;
}

unsigned short CUDPCommunication::CalculateUDPChecksum(unsigned char* UserData, int UserDataLen, UINT SourceIP, UINT DestIP, 
	USHORT SourcePort, USHORT DestinationPort, UCHAR Protocol, unsigned char* FinalPacket)
{
	unsigned short CheckSum = 0;
	unsigned short PseudoLength = UserDataLen + 8 + 9;  //Length of PseudoHeader = Data Length + 8 bytes UDP header (2Bytes Length,2 Bytes Dst Port, 2 Bytes Src Port, 2 Bytes Checksum)
	//+ Two 4 byte IP's + 1 byte protocol
	PseudoLength += PseudoLength % 2;					//If bytes are not an even number, add an extra.
	unsigned short Length = UserDataLen + 8;			// This is just UDP + Data length. needed for actual data in udp header

	unsigned char* PseudoHeader = new unsigned char[PseudoLength];
	RtlZeroMemory(PseudoHeader, PseudoLength);

	PseudoHeader[0] = 0x11;

	memcpy((void*)(PseudoHeader + 1), (void*)(FinalPacket + 26), 8); // Source and Dest IP

	Length = htons(Length);
	memcpy((void*)(PseudoHeader + 9), (void*)&Length, 2);
	memcpy((void*)(PseudoHeader + 11), (void*)&Length, 2);
	memcpy((void*)(PseudoHeader + 13), (void*)(FinalPacket + 34), 2);
	memcpy((void*)(PseudoHeader + 15), (void*)(FinalPacket + 36), 2);
	memcpy((void*)(PseudoHeader + 17), (void*)UserData, UserDataLen);

	for (int i = 0; i < PseudoLength; i += 2)
	{
		unsigned short Tmp = BytesTo16(PseudoHeader[i], PseudoHeader[i + 1]);
		unsigned short Difference = 65535 - CheckSum;
		CheckSum += Tmp;
		if (Tmp > Difference) { CheckSum += 1; }
	}
	CheckSum = ~CheckSum;								//One's complement

	delete PseudoHeader;

	return CheckSum;
}

unsigned short CUDPCommunication::BytesTo16(unsigned char X, unsigned char Y)
{
	unsigned short Tmp = X;
	Tmp = Tmp << 8;
	Tmp = Tmp | Y;
	return Tmp;
}

unsigned short CUDPCommunication::CalculateIPChecksum(UINT TotalLen, UINT ID, UINT SourceIP, UINT DestIP, unsigned char* FinalPacket)
{
	unsigned short CheckSum = 0;
	for (int i = 14; i < 34; i += 2)
	{
		unsigned short Tmp = BytesTo16(FinalPacket[i], FinalPacket[i + 1]);
		unsigned short Difference = 65535 - CheckSum;
		CheckSum += Tmp;
		if (Tmp > Difference) { CheckSum += 1; }
	}
	CheckSum = ~CheckSum;
	return CheckSum;
}



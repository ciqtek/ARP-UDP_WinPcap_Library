#define MAP_SIZE 4
#define WIN32

#include <mutex>
#include <chrono>

#include "QMCFindDevice.h"
#include "WinPcap/Include/pcap.h"
#include "net_helper/net_helper.h"
#include "windows.h"

#pragma comment(lib,"Ws2_32.lib")

#define LIBPATH(p,f)   p##f
#ifdef _WIN64
#pragma comment(lib,LIBPATH(__FILE__,"/../WinPcap/Lib/x64/wpcap.lib"))
#else
#pragma comment(lib,LIBPATH(__FILE__,"/../WinPcap/Lib/wpcap.lib"))
#endif // _WIN64


#pragma pack(1)
struct DLCHeader
{
	unsigned char DesMAC[6]; //目的MAC地址
	unsigned char SrcMAC[6]; //源MAC地址
	unsigned short EType;    //帧类型
};//c语言的内存对齐 2
#pragma pack()


#pragma pack(1)
struct ARPFrame
{
	unsigned short HW_Type;           //hardware type
	unsigned short Pro_Type;          //protocol type
	unsigned char  HW_len;            //MAC address length
	unsigned char  Pro_len;           //protocol length
	unsigned short Flag;              //1:request , 2:reply
	unsigned char  Send_HW_Addr[6];   //sender's mac address
	unsigned int   Send_Pro_Addr;	  //sender's ip address
	unsigned char  Targ_HW_Addr[6];   //source mac address
	unsigned int   Targ_Pro_Addr;     //source ip address
	unsigned char  Padding[18];       //Padding data
};//以2个字节为对齐
#pragma pack()


#pragma pack(1)
struct ARPPacket
{
	DLCHeader dlcHeader;
	ARPFrame  arpFrame;
};//60个字节
#pragma pack()


#ifdef USE_PORT_CHECK
#pragma pack(1)
struct ArpHeaderStructure
{
	unsigned char  TargetMac[6];//目标MAC地址
	unsigned char  SourceMac[6];//源MAC地址
	unsigned short TypesOf;//类型
	unsigned short HardwareType;//硬件类型
	unsigned short AgreementType;//协议类型
	unsigned char  HardwareAddressLength;//硬件地址长度
	unsigned char  LengthOfAgreement;//协议长度
	unsigned short TypeOfOperation;//操作类型
	unsigned char  SourceMacAddress[6];//源MAC地址
	unsigned int   SourceIpAddress;//源IP地址
	unsigned char  TargetMacAddress[6];//目标MAC地址
	unsigned int   TargetIpAddress;//目标IP地址
	unsigned char  FindFlag[6];//设备搜索标志
	unsigned char  Persist[PERSIST_LEN];//保留
	uint16_t	   Port;//自定义端口
};
#pragma pack()
#else
#pragma pack(1)
struct ArpHeaderStructure
{
	unsigned char  TargetMac[6];//目标MAC地址
	unsigned char  SourceMac[6];//源MAC地址
	unsigned short TypesOf;//类型
	unsigned short HardwareType;//硬件类型
	unsigned short AgreementType;//协议类型
	unsigned char  HardwareAddressLength;//硬件地址长度
	unsigned char  LengthOfAgreement;//协议长度
	unsigned short TypeOfOperation;//操作类型
	unsigned char  SourceMacAddress[6];//源MAC地址
	unsigned int   SourceIpAddress;//源IP地址
	unsigned char  TargetMacAddress[6];//目标MAC地址
	unsigned int   TargetIpAddress;//目标IP地址
	unsigned char  FindFlag[6];//设备搜索标志
	unsigned char  Persist[PERSIST_LEN];//保留
};
#pragma pack()
#endif // USE_PORT_CHECK

struct adaptor_info
{
	arp_net::net_ada_list::iterator it;
	std::string name;
	std::string ip;
	std::string mac;
	std::string device_ip;
	std::string device_mac;
	unsigned int netmask;
	char message[PERSIST_LEN];

	bool operator==(adaptor_info& other)
	{
		if (this->device_ip == other.device_ip
			&& this->device_mac == other.device_mac
			&& this->ip == other.ip
			&& this->mac == other.mac)
		{
			return true;
		}

		return false;
	}
};

static std::mutex mux;

static bool CreateBareMac(std::string mac, std::string&bare_mac)
{
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
	return true;
}

static std::string GetShowMac(unsigned char* hex_mac)
{
	std::string show_mac;
	for (int i = 0; i < 6; ++i)
	{
		uint8_t value;
		memcpy(&value, hex_mac + i, 1);
		char temp[4] = { 0 };
		sprintf_s(temp, "%02X-", value);
		show_mac.append(temp);
	}
	show_mac.pop_back();
	return std::move(show_mac);
}

static unsigned char* GetHexMac(std::string mac)
{
	std::string bare_mac;
	if (!CreateBareMac(mac, bare_mac))
	{
		return nullptr;
	}

	unsigned char* hex_mac = new unsigned char[6];

	int pos = 0;
	for (int i = 0; i < 12; i += 2)
	{
		std::string ch = bare_mac.substr(i, 2);
		try
		{
			unsigned char num = std::stoi(ch, nullptr, 16);
			hex_mac[pos] = num;
			++pos;
		}
		catch (const std::exception&)
		{
			if (hex_mac)
			{
				delete[] hex_mac;
				hex_mac = nullptr;
			}
			break;
		}
	}

	return hex_mac;
}


static void StrToHex(char *pbDest, char *pbSrc, int nLen)
{
	char h1, h2;
	unsigned char s1, s2;
	int i;

	for (i = 0; i < nLen; i++)
	{
		h1 = pbSrc[2 * i];
		h2 = pbSrc[2 * i + 1];

		s1 = toupper(h1) - 0x30;
		if (s1 > 9)
			s1 -= 7;

		s2 = toupper(h2) - 0x30;
		if (s2 > 9)
			s2 -= 7;

		pbDest[i] = s1 * 16 + s2;
	}
}

static uint16_t CreateNoRepeatNum()
{
	HANDLE mem_handle = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, "Global/CiqtekQMCPort");
	if (!mem_handle)
	{
		DWORD err = GetLastError();
		if (err != ERROR_FILE_NOT_FOUND)
		{
			return 0;
		}

		mem_handle = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL,
			PAGE_READWRITE, 0, MAP_SIZE, "Global/CiqtekQMCPort");

		if (!mem_handle)
		{
			return 0;
		}
	}

	LPVOID view = MapViewOfFile(mem_handle, FILE_MAP_ALL_ACCESS, 0, 0, MAP_SIZE);
	if (!view)
	{
		CloseHandle(mem_handle);
		return 0;
	}
	
	HANDLE mux_handle = CreateMutexA(NULL,TRUE,"Global/CiqtekQMCPortMutex");
	if (!mux_handle)
	{
		UnmapViewOfFile(view);
		CloseHandle(mem_handle);
		return 0;
	}

	WaitForSingleObject(mux_handle, INFINITE);

	uint16_t value[2];
	memcpy(value, view, sizeof(value));
	if ((value[0] & 0x5a5a) == 0x5a5a)
	{
		value[1] = (value[1] != 65535) ? value[1] + 1 : 8080;
	}
	else
	{
		value[0] = 0x5a5a;
		value[1] = 8080;
	}
	memcpy(view, value, sizeof(value));
	ReleaseMutex(mux_handle);
	
	UnmapViewOfFile(view);
	CloseHandle(mux_handle);
	return value[1];
}

static ARPPacket* CreateArpPacket(std::string ip, std::string mac,uint16_t port)
{
	//创建包内存
	ARPPacket* arpPacket = new ARPPacket;
	memset(arpPacket, 0, sizeof(ARPPacket));

	//构造以太网头部
	unsigned char * dest_mac = GetHexMac("FF-FF-FF-FF-FF-FF");
	if (!dest_mac)
	{
		return nullptr;
	}
	memcpy(arpPacket->dlcHeader.DesMAC, dest_mac, 6);
	memcpy(arpPacket->arpFrame.Targ_HW_Addr, dest_mac, 6);
	delete[] dest_mac;

	unsigned char * src_mac = GetHexMac(mac);
	if (!src_mac)
	{
		return nullptr;
	}
	memcpy(arpPacket->dlcHeader.SrcMAC, src_mac, 6);
	memcpy(arpPacket->arpFrame.Send_HW_Addr, src_mac, 6);
	delete[] src_mac;

	arpPacket->dlcHeader.EType = htons((unsigned short)0x0806);

	//构造ARP协议头部
	arpPacket->arpFrame.HW_Type = htons((unsigned short)1);
	arpPacket->arpFrame.Pro_Type = htons((unsigned short)0x0800);
	arpPacket->arpFrame.HW_len = (unsigned char)6;
	arpPacket->arpFrame.Pro_len = (unsigned char)4;
	arpPacket->arpFrame.Flag = htons((unsigned short)0x0001);

	unsigned int src_ip;
	inet_pton(AF_INET, ip.c_str(), &src_ip);
	arpPacket->arpFrame.Send_Pro_Addr = src_ip;

	unsigned int dest_ip;
	inet_pton(AF_INET, "255.255.255.255", &dest_ip);
	arpPacket->arpFrame.Targ_Pro_Addr = dest_ip;

	uint16_t flag = htons(0x55aa);
	uint16_t padding[4] = { flag,flag,flag,htons(port) };

	memcpy(arpPacket->arpFrame.Padding, padding, sizeof(padding));  //数据

	return arpPacket;
}

int QMCFindDevice(std::vector<QMCDeviceInfo>& device_infos)
{
#ifdef USE_PORT_CHECK
	bool check_port = true;
	static uint16_t port = CreateNoRepeatNum();
	if (port == 0)
	{
		check_port = false;
	}
#endif // USE_PORT_CHECK

	using namespace arp_net;
	net_adapter_helper& helper = net_adapter_helper::get_instance();

	net_ada_list ada_list = helper.get_info_win();

	if (ada_list.size() <= 0)
	{
		return 0;
	}

	std::vector<adaptor_info> valid_ada;
	for (auto _it = ada_list.begin(); _it != ada_list.end(); ++_it)
	{
		if (_it->_dev_type == "WIRELESS" || _it->_ip_size <= 0)
		{
			continue;
		}

		for (int i = 0; i < _it->_ip_size; ++i)
		{
			if (!_it->_ip[i]._inet4.empty() && _it->_ip[i]._inet4 != "0.0.0.0")
			{
				adaptor_info temp;
				temp.it = _it;
				temp.ip = _it->_ip[i]._inet4;
				temp.name = "\\Device_\\NPF_" +  _it->_name;
				temp.mac = _it->_mac;
				inet_pton(AF_INET, _it->_ip[i]._subnet_mask.c_str(), &temp.netmask);
				valid_ada.push_back(temp);
			}
		}
	}
	if (valid_ada.size() <= 0)
	{
		return 0;
	}
	
	std::vector<adaptor_info> response_ada;
	char error_buffer[PCAP_ERRBUF_SIZE] = { 0 };
	mux.lock();
	for (auto _it = valid_ada.begin(); _it != valid_ada.end(); ++_it)
	{
		pcap_t* handler = pcap_open_live(_it->name.c_str(), 65535, 1, 100, error_buffer);
		if (!handler)
		{
			continue;
		}

		//添加过滤器 失败则不添加设备过滤器
		bpf_program fcode;
		if (pcap_compile(handler, &fcode, ("arp dst host " + _it->ip + " and ether dst " + _it->mac).c_str(),1, _it->netmask) == 0)
		{
			pcap_setfilter(handler, &fcode);
		}

		ARPPacket* send_packet = nullptr;
#ifdef USE_PORT_CHECK
		if (check_port)
		{
			send_packet  = CreateArpPacket(_it->ip, _it->mac, port);
		}
#else 
		send_packet = CreateArpPacket(_it->ip, _it->mac, 0);
#endif // USE_PORT_CHECK

		if (!send_packet)
		{
			pcap_close(handler);
			continue;
		}

		if (pcap_sendpacket(handler, (const u_char*)send_packet, sizeof(ARPPacket)) < 0)
		{
			delete send_packet;
			pcap_close(handler);
			continue;
		}

		pcap_pkthdr* pkthdr = nullptr;
		const u_char* pkt_data = nullptr;
		int times_flag = 0;
		while (true)
		{
			int ret = pcap_next_ex(handler, &pkthdr, &pkt_data);
			if (ret == 1)
			{
				//for (uint16_t i = 0; i < pkthdr->len; i++)
				//{
				//	fprintf(stdout, "%02X ", pkt_data[i]);
				//	if ((i + 1) % 14 == 0)
				//	{
				//		fprintf(stdout, "\n");
				//	}
				//}
				//fprintf(stdout, "\n");

				if (pkthdr->caplen != sizeof(ArpHeaderStructure))
				{
					continue;
				}

				ArpHeaderStructure* arp_response = (ArpHeaderStructure*)pkt_data;
				uint16_t flag[3] = { htons(0x55aa),htons(0x55aa),htons(0x55aa) };
				bool check_port_result = true;
#ifdef USE_PORT_CHECK 
				if (check_port)
				{
					check_port_result = port == ntohs(arp_response->Port);
				}
#endif // USE_PORT_CHECK 
				if (memcmp(arp_response->FindFlag, &flag, sizeof(flag)) == 0 && check_port_result)
				{
					char device_ip[124] = { 0 };
					inet_ntop(AF_INET, &arp_response->SourceIpAddress, device_ip, sizeof(device_ip));
					_it->device_ip = std::move(std::string(device_ip));

					_it->device_mac = GetShowMac(arp_response->SourceMacAddress);
					memcpy(_it->message, arp_response->Persist, sizeof(arp_response->Persist));
					
#ifndef USE_PORT_CHECK
					//通过遍历的方式保证进程之间互斥
					bool has_find_same = false;
					for (auto iter = response_ada.begin(); iter != response_ada.end(); ++iter)
					{
						if (*iter == *_it)
						{
							has_find_same = true;
							break;
						}
					}

					if (has_find_same)
					{
						continue;
					}
#endif // !USE_PORT_CHECK
					response_ada.push_back(*_it);
				}
			}
			else
			{
				if (!response_ada.empty())
				{
					break;
				}

				if (times_flag)
				{
					break;
				}

				++times_flag;
			}
		}
		delete send_packet;
		pcap_close(handler);
	}
	mux.unlock();
	for (auto _it = response_ada.begin(); _it != response_ada.end(); ++_it)
	{
		QMCDeviceInfo info;
		info.local_ip = _it->ip;
		info.local_mac = _it->mac;
		info.device_ip = _it->device_ip;
		info.device_mac = _it->device_mac;
		info.local_adaptor_dsp = _it->it->_description;

		memcpy(info.message,_it->message,sizeof(_it->message));

		device_infos.push_back(std::move(info));
	}

	return response_ada.size();
}





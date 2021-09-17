#ifndef CUDPCOMMUNICATION_H
#define CUDPCOMMUNICATION_H

#include <iostream>
#include <atomic>
#include <mutex>

#include "WinPcap/Include/pcap.h"

class CUDPCommunication
{
private:
	//��̫��ͷ��(14)
#pragma pack(1)
	struct EthernetHeader
	{
		unsigned char  TargetMacAddress[6];//Ŀ��MAC��ַ
		unsigned char  SourceMacAddress[6];//ԴMAC��ַ
		unsigned short TypesOf;//����
	};
#pragma pack()

	//IPЭ��ͷ�ṹ(20)
#pragma pack(1)
	struct IpSeaderStructure
	{
		unsigned char  Version_HeadLength;//�汾��ͷ����
		unsigned char  ServiceType;//��������
		unsigned short TotalLengthOfPacket;//����ܳ���
		unsigned short PacketIdentification;//�����ʶ
		unsigned short FragmentOffsetAddress;//Ƭ��ƫ�Ƶ�ַ
		unsigned char  SurvivalTime;//���ʱ��
		unsigned char  Protocol;//Э��
		unsigned short Checksum;//У���
		unsigned int   SourceIpAddress;//ԴIP��ַ
		unsigned int   TargetIpAddress;//Ŀ��IP��ַ
	};
#pragma pack()

	//UDPЭ��ͷ�ṹ(8)
#pragma pack(1)
	struct UdpHeaderStructure
	{
		unsigned short SourcePort;//Դ�˿�
		unsigned short DestinationPort;//Ŀ�Ķ˿�
		unsigned short PacketLength;//�������
		unsigned short Checksum;//У���
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

	/*�洢�������� ���ⴴ��UDP�������ظ�ת��*/
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
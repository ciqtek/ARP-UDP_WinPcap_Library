
//*************************************************************************************************
// ����:����WinPcap����������ͨѶ���ARPЭ���UDPЭ����Զ���ͨѶ��
//
// �÷�:ֱ�ӽ������ļ���������main.cpp�ļ�����������Ŀ�У���Դ�����ʽʹ�ã�main.cpp�д�ŵ��ǽӿ�ʹ�ð���
//
// �ص�:֧�ֿ�����ͨѶ ֧�ֶ��豸ͬʱͨѶ ������������ �̰߳�ȫ
//
// ����:������������� QMCС��
//*************************************************************************************************

#include <iostream>
#include <thread>
#include <future>

#include "Winsock2.h"
#include "QMCFindDevice.h"
#include "UDPCommunication.h"

#pragma pack(1)
struct ReadPackage
{
	uint16_t head1 = 0x5555;
	uint16_t head2 = 0xaaaa;
	uint16_t cmd = 0x0200;
	uint16_t len = 0x0200;
	uint16_t addr;
};
#pragma pack()

#pragma pack(1)
typedef struct WritePackage
{
	uint16_t head1 = 0x5555;
	uint16_t head2 = 0xaaaa;
	uint16_t cmd;
	uint16_t len = 0x0600;
	uint16_t addr;
	uint32_t data;
}ReadReplyPackage;
#pragma pack()


std::mutex print_mux;

void communication(std::string local_ip, std::string local_mac, std::string device_ip, std::string device_mac)
{
	CUDPCommunication comm;
	/*step3: ����UDPͨѶ���󣬰��豸IP MAC�ͱ���������IP MAC*/
	if (!comm.Bind(local_ip, local_mac, device_ip, device_mac))
	{
		printf("comm1 Connect():failed\n");
		return;
	}

	/*step4: ���ݲ�ͬ�豸���˵�ͨѶЭ�� ��Ӧ�ò������� �˰����������һ����AWG 0x0000 �Ĵ����������*/
	ReadPackage packet;
	packet.addr = htons(0x0000);

	while (true)
	{
		/*step5: ѭ��д���������λ��*/
		comm.Write(32000, 32000, (unsigned char*)&packet, sizeof(ReadPackage));
		using namespace std::chrono_literals;
		std::this_thread::sleep_until(std::chrono::system_clock::now() + 1000ms);

		/*step6: ѭ����ȡ��λ����������λ���������*/
		unsigned char buffer[1024] = { 0 };
		int len = comm.Read(32000, buffer, 1024);

		print_mux.lock();
		printf_s("thread%d:",std::this_thread::get_id());
		if (len <= 0)
		{
			printf_s("\n");
		}
		for (uint16_t i = 0; i < len; i++)
		{
			fprintf(stdout, "%02X ", buffer[i]);
			if ((i + 1) % 14 == 0)
			{
				fprintf(stdout, "\n");
			}
		}
		print_mux.unlock();
	}
}

/*���豸ͬʱͨѶ����*/
void example1()
{
	/*step1: ���û���ARPЭ��Ľӿ������豸����ȡ�豸��IP��MAC�Լ������������豸ͨѶ������IP��MAC*/
	std::vector<QMCDeviceInfo> infos;
	int ret = QMCFindDevice(infos);

	std::cout << "Has Find " << ret << " Device" << std::endl;

	if (!ret)
	{
		std::cout << "Exit Usage Program" << std::endl;
	}

	/*note: �����ܹ�֧�ֶ��豸ͬʱͨѶ���̰߳�ȫ*/
	std::vector<std::future<void>> all_future;
	for (auto it = infos.begin(); it != infos.end(); ++it)
	{
		/*step2��Ϊÿ���豸�����߳� ���ж��豸ͨѶ*/
		auto future = std::async(std::launch::async, communication, it->local_ip, it->local_mac, it->device_ip, it->device_mac);
		all_future.push_back(std::move(future));
	}
}

/*���߳���������*/
void example2()
{
	std::future<void> fu1 = std::async(std::launch::async, [&]()
	{
		while (true)
		{
			std::vector<QMCDeviceInfo> infos;
			int ret = QMCFindDevice(infos);
			std::cout << "thread " << std::this_thread::get_id() << " find " << ret << " device" << std::endl;
		}
	});

	std::future<void> fu2 = std::async(std::launch::async, [&]()
	{
		while (true)
		{
			std::vector<QMCDeviceInfo> infos;
			int ret = QMCFindDevice(infos);
			std::cout << "thread " << std::this_thread::get_id() << " find " << ret << " device" << std::endl;
		}
	});

	std::future<void> fu3 = std::async(std::launch::async, [&]()
	{
		while (true)
		{
			std::vector<QMCDeviceInfo> infos;
			int ret = QMCFindDevice(infos);
			std::cout << "thread " << std::this_thread::get_id() << " find " << ret << " device" << std::endl;
		}
	});
}

/*��ʾĳ������ ֱ�ӵ��ö�Ӧ��example��������*/
int main(int argc, char *argv[])
{
	example1();
}

//*************************************************************************************************
// 名称:基于WinPcap第三方网络通讯库的ARP协议和UDP协议的自定义通讯库
//
// 用法:直接将所有文件（不包括main.cpp文件）拷贝到项目中，以源码的形式使用，main.cpp中存放的是接口使用案例
//
// 特点:支持跨网段通讯 支持多设备同时通讯 屏蔽无线网卡 线程安全
//
// 作者:国仪量子软件部 QMC小组
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
	/*step3: 创建UDP通讯对象，绑定设备IP MAC和本机网卡的IP MAC*/
	if (!comm.Bind(local_ip, local_mac, device_ip, device_mac))
	{
		printf("comm1 Connect():failed\n");
		return;
	}

	/*step4: 根据不同设备与后端的通讯协议 组应用层的网络包 此案例中组的是一个读AWG 0x0000 寄存器的网络包*/
	ReadPackage packet;
	packet.addr = htons(0x0000);

	while (true)
	{
		/*step5: 循环写网络包到下位机*/
		comm.Write(32000, 32000, (unsigned char*)&packet, sizeof(ReadPackage));
		using namespace std::chrono_literals;
		std::this_thread::sleep_until(std::chrono::system_clock::now() + 1000ms);

		/*step6: 循环读取下位机发送至上位机的网络包*/
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

/*多设备同时通讯案例*/
void example1()
{
	/*step1: 调用基于ARP协议的接口搜索设备，获取设备的IP和MAC以及本机可以与设备通讯的网卡IP和MAC*/
	std::vector<QMCDeviceInfo> infos;
	int ret = QMCFindDevice(infos);

	std::cout << "Has Find " << ret << " Device" << std::endl;

	if (!ret)
	{
		std::cout << "Exit Usage Program" << std::endl;
	}

	/*note: 本库能够支持多设备同时通讯、线程安全*/
	std::vector<std::future<void>> all_future;
	for (auto it = infos.begin(); it != infos.end(); ++it)
	{
		/*step2：为每个设备创建线程 进行多设备通讯*/
		auto future = std::async(std::launch::async, communication, it->local_ip, it->local_mac, it->device_ip, it->device_mac);
		all_future.push_back(std::move(future));
	}
}

/*多线程搜索案例*/
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

/*演示某个案例 直接调用对应的example函数即可*/
int main(int argc, char *argv[])
{
	example1();
}
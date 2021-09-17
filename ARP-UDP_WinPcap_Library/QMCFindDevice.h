#ifndef QMC_FIND_DEVICE_H
#define QMC_FIND_DEVICE_H

//#define USE_PORT_CHECK

#ifdef USE_PORT_CHECK
#define PERSIST_LEN 16
#else
#define PERSIST_LEN 18
#endif // USE_PORT_CHECK

#include <string>
#include <vector>

struct QMCDeviceInfo
{
	std::string local_adaptor_dsp;
	std::string local_ip;
	std::string local_mac;
	std::string device_ip;
	std::string device_mac;
	unsigned char message[PERSIST_LEN];
};

int QMCFindDevice(std::vector<QMCDeviceInfo>& device_infos);

#endif // !QMC_FIND_DEVICE_H

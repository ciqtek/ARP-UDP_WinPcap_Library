#include "net_helper.h"

#include <memory>
#include <string>

#if defined(os_is_win)
#include <WinSock2.h>
#include <Iphlpapi.h>
#pragma comment(lib,"iphlpapi.lib")
#endif //! defined(os_is_win)

namespace arp_net
{

	/**
	*	@brief:
	*/
	arp_net::net_adapter_helper& net_adapter_helper::get_instance()
	{
		static net_adapter_helper instance;

		return instance;
	}


	/**
	*	@brief:
	*/
	arp_net::net_ada_list net_adapter_helper::get_info_win()
	{
		net_ada_list ret_list;

		std::unique_ptr<IP_ADAPTER_INFO> pai(new(std::nothrow) IP_ADAPTER_INFO);

		// 1. failed to apply space
		if (nullptr == pai || NULL == pai)
			return ret_list;

		// 2. to get the size of IP_ADAPTER_INFO structure 
		unsigned long iai_size = sizeof(IP_ADAPTER_INFO);

		// 3.调用GetAdaptersInfo函数, 填充pIpAdapterInfo指针变量; 其中stSize参数既是一个输入量也是一个输出量
		int ret_val = GetAdaptersInfo(pai.get(), &iai_size);

		if (ERROR_BUFFER_OVERFLOW == ret_val)
		{
			//pai.release();

			//重新申请内存空间用来存储所有网卡信息
			pai.reset((IP_ADAPTER_INFO*)(new(std::nothrow) char[iai_size]));

			if (nullptr == pai || NULL == pai)
			{
				return ret_list;
			}

			//再次调用GetAdaptersInfo函数,填充pIpAdapterInfo指针变量
			ret_val = GetAdaptersInfo(pai.get(), &iai_size);
		}

		if (ERROR_SUCCESS == ret_val)
		{
			// 3. to get information 
			net_ada_info item;
			IP_ADAPTER_INFO *ppai = pai.get();

			while (ppai)
			{
				item._index = ppai->Index;
				item._name = std::string(ppai->AdapterName);
				item._description = std::string(ppai->Description);

				// dev
				std::string str_type;
				switch (ppai->Type)
				{
				case MIB_IF_TYPE_OTHER:
					str_type = { "OTHER" };
					break;

				case MIB_IF_TYPE_ETHERNET:
					str_type = { "ETHERNET" };
					break;

				case MIB_IF_TYPE_TOKENRING:
					str_type = { "TOKENRING" };
					break;

				case MIB_IF_TYPE_FDDI:
					str_type = { "FDDI" };
					break;

				case MIB_IF_TYPE_PPP:
					str_type = { "PPP" };
					break;

				case MIB_IF_TYPE_LOOPBACK:
					str_type = { "LOOPBACK" };
					break;

				case MIB_IF_TYPE_SLIP:
					str_type = { "SLP" };
					break;

				case IF_TYPE_IEEE80211:
					str_type = { "WIRELESS" };
					break;

				default:
					str_type = { "" };
					break;
				}

				item._dev_type = str_type;

				// mac
				std::string str_mac;
				for (DWORD i = 0; i < ppai->AddressLength; i++)
				{
					if (i < ppai->AddressLength - 1)
						str_mac += str_format("%02X-", ppai->Address[i]);
					else
						str_mac += str_format("%02X", ppai->Address[i]);
				}

				item._mac = str_mac;

				// ip information
				ip_info ii_item;
				IP_ADDR_STRING *pial = &(ppai->IpAddressList);
				int ip_size = 0;
				for (;;)
				{
					if (NULL != pial && nullptr != pial)
					{
						ii_item._inet4 = std::string(pial->IpAddress.String);
						ii_item._subnet_mask = std::string(pial->IpMask.String);
						ii_item._gate = std::string(pai->GatewayList.IpAddress.String);

						item._ip.emplace_back(ii_item);
						pial = pial->Next;
						ii_item.zero();
						ip_size++;
					}
					else
					{
						break;
					}
				}

				item._ip_size = ip_size;
				ret_list.emplace_back(item);
				item.zero();

				ppai = ppai->Next;
			} // end while
		}
		else
		{
			;// error
		}

		return std::move(ret_list);
	}

	std::string net_adapter_helper::GetSubnetMask(const std::string &local_ip)
	{
		net_ada_list ret_list(std::move(get_info_win()));
		for (auto item : ret_list)
		{
			for (auto item_ip : item._ip)
			{
				if (local_ip == item_ip._inet4)
				{
					return item_ip._subnet_mask;
				}
			}
		}
		return std::string();
	}
}

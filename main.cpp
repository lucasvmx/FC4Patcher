#include <bits/stdc++.h>
#include <chrono>
#include <thread>
#include "include/init.h"
#include "include/process.h"

using namespace std;

#define MODULE_NAME "FC64.dll"
#define PROCESS_NAME "FarCry4.exe"
#define count(x) (sizeof(x)/sizeof(x[0]))

unsigned char buff[16];

unsigned char *generate_shellcode(int len)
{
    const int limit = static_cast<int>(count(buff));

    if(len >= limit) {
        cout << "Buffer is too big. Maximum allowed size is " << len;
        return NULL;
    }

    memset(&buff, 0, sizeof(buff));

    for(int i = 0; i < limit; i++)
    {
        buff[i] = '\x90';
    }

    return &buff[0];
}

void applyPatches(libhack_handle *handle, DWORD64 modAddr)
{
    unsigned char *sc1 = generate_shellcode(3);
    unsigned char *sc2 = generate_shellcode(6);
    vector<pair<DWORD64,int>> addresses = vector<pair<DWORD64,int>>();
	size_t failures = 0;
	const int player_money = 950000;

    addresses.push_back(make_pair<DWORD64,int>(modAddr + 0x12bab25, 3));
    addresses.push_back(make_pair<DWORD64,int>(modAddr + 0x12bab36, 6));
    addresses.push_back(make_pair<DWORD64, int>(modAddr + 0xb843a7, 3));

	auto calculate_money_address = [&]() -> __int64 {
		const int offsets[] = {0x18, 0x0, 0x150, 0xa0, 0x70, 0xd30, 0x5b8};
		__int64 address = modAddr + 0x02def618;

		// calculates money address
		for(const auto& offset : offsets) {
			auto x = libhack_read_int64_from_addr64(handle, address);
			address = x + offset;
		}

		return address;
	};

	__int64 money_addr = calculate_money_address();

	cout << "money is at: " << money_addr << endl;

    for_each(addresses.begin(), addresses.end(), [&](const pair<DWORD64,int>& p) {
		int bytes_written = 0;

        cout << "Writing shellcode at address " << p.first << endl;

		if(p.second == 3) {
			bytes_written = libhack_write_string_to_addr64(handle, p.first, reinterpret_cast<const char *>(sc1), p.second);
		} else if(p.second == 6) {
			bytes_written = libhack_write_string_to_addr64(handle, p.first, reinterpret_cast<const char*>(sc2), p.second);
		}

		if(bytes_written <= 0) {
			cout << "Failed to patch address " << p.first << endl;
			failures++;
		}
    });

	if(failures == addresses.size()) {
		cout << "We failed to apply all patches :(" << endl;
	} else {
		cout << dec;
		cout << "Patches applied: " << addresses.size() - failures << endl;
	}

	cout << "Patching player money ..." << endl;
	for(;;) {
		libhack_write_int_to_addr64(handle, money_addr, player_money);
		this_thread::sleep_for(chrono::seconds(5));
	}
}

int main()
{
    cout << "loading libhack ..." << endl;

    struct libhack_handle *lh = libhack_init(PROCESS_NAME);

    if(lh == nullptr) {
        cout << "failed to allocate memory" << endl;
        return 1;
    }

    while(!libhack_open_process(lh)) {
        cout << "waiting far cry to be opened" << endl;
        this_thread::sleep_for(chrono::seconds(5));
    }

    cout << "Far cry is running: " << lh->bProcessIsOpen << endl;
    this_thread::sleep_for(chrono::seconds(5));

    cout << "Trying to get address of " << MODULE_NAME << endl;

    // calcula os offsets
    DWORD64 addr = libhack_getsubmodule_addr64v2(lh, MODULE_NAME);

    cout << showbase << internal << setfill('0');

    if(addr == 0) {
        cout << "Failed to get address of " << MODULE_NAME << endl;
        cout << "Trying to enumerate 32 bits modules" << endl;
        auto addr32 = libhack_getsubmodule_addr(lh, MODULE_NAME);
        if(addr32 == 0) {
            cout << "Failed to get addr" << endl;
            libhack_free(lh);
            return 1;
        }

        cout << "Address of " << MODULE_NAME << ": " << hex << addr32 << endl;
        addr = static_cast<DWORD64>(addr32);
    }

    cout << "Address of " << MODULE_NAME << ": " << hex << addr << endl;

    applyPatches(lh, addr);

    return 0;
}
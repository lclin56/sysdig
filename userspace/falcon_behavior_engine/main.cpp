#include "fbeng.h"
#include <iostream>
#include <getopt.h>
#include <string>
#include "logcxx.h"

void print_usage()
{
	std::cout << "Usage: fbeng_tool [options]\n"
			  << "Options:\n"
			  << "  -p, --pattern       Pattern file path (default: fbeng.ptn)\n"
			  << "  -d, --temp-dir      Temporary directory path (default: /tmp/tempfbeng)\n"
			  << "  -t, --timeout       Timeout for scanning scap files in seconds (default: 180)\n"
			  << "  -n, --max-events    Maximum number of events from scap file (default: 1000000)\n"
			  << "  -f, --filter-string Filter string for scanning (default: none)\n"
			  << "  -k, --token         Token string (default: FBE_TEST_KEY)\n"
			  << "  -s, --scap-file     Scap file path (required)\n"
			  << "  -l, --evt-log-file  Event log file path (default: evt_log.json)\n"
			  << "  -o, --log-level     Logging level (default: error)\n"
			  << "  -r, --rule     		scan by a rule file (default: null)\n"
			  << "  -h, --help          Display this help message and exit\n";
}

void log_call_func(const char *msg)
{
	std::cout << msg;
}

int main(int argc, char **argv)
{
	int opt;
	int option_index = 0;
	struct option long_options[] = {
		{"pattern", optional_argument, 0, 'p'},
		{"temp-dir", optional_argument, 0, 'd'},
		{"timeout", optional_argument, 0, 't'},
		{"max-events-num", optional_argument, 0, 'n'},
		{"filter-string", optional_argument, 0, 'f'},
		{"token", optional_argument, 0, 'k'},
		{"scap-file", required_argument, 0, 's'},
		{"evt-log-file", optional_argument, 0, 'l'},
		{"log-level", optional_argument, 0, 'o'},
		{"rule", optional_argument, 0, 'r'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}};

	std::string pattern = "fbeng.ptn";
	std::string temp_dir = "/tmp/tempfbeng";
	int timeout = 180;
	size_t max_events_num = 1000000;
	std::string filter_string;
	std::string token = "FBE_TEST_KEY";
	std::string scap_file;
	std::string evt_log_file = "evt_log.json";
	int log_level = LOG_LEVEL_ERROR;
	std::string rule;

	while ((opt = getopt_long(argc, argv, "p:d:t:n:f:k:s:l:o:r:h", long_options, &option_index)) != -1)
	{
		switch (opt)
		{
		case 'p':
			pattern = optarg;
			break;
		case 'd':
			temp_dir = optarg;
			break;
		case 't':
			try
			{
				timeout = std::stoi(optarg);
			}
			catch (const std::exception &e)
			{
				std::cerr << e.what() << '\n';
			}
			break;
		case 'n':
			try
			{
				max_events_num = std::stoll(optarg);
			}
			catch (const std::exception &e)
			{
				std::cerr << e.what() << '\n';
			}
			break;
		case 'f':
			filter_string = optarg;
			break;
		case 'k':
			token = optarg;
			break;
		case 's':
			scap_file = optarg;
			break;
		case 'l':
			evt_log_file = optarg;
			break;
		case 'o':
			if (std::string(optarg) == "debug")
			{
				log_level = LOG_LEVEL_DEBUG;
			}
			else if (std::string(optarg) == "info")
			{
				log_level = LOG_LEVEL_INFO;
			}
			else if (std::string(optarg) == "warn")
			{
				log_level = LOG_LEVEL_WARN;
			}
			else if (std::string(optarg) == "error")
			{
				log_level = LOG_LEVEL_ERROR;
			}
			break;
		case 'r':
			rule = std::string(optarg);
			break;
		case 'h':
		case '?':
			print_usage();
			return 0;
		default:
			print_usage();
			return 1;
		}
	}

	if (scap_file.empty())
	{
		std::cerr << "Please input a scap file to scan..." << std::endl;
		print_usage();
		return 1;
	}

	FBEngine *fbe = new FBEngine();

	FBConf conf = {
		.pattern_path = pattern,
		.temp_dir = temp_dir,
		.token = token,
		.log_mode = LOG_MODE_CALLBACK,
		.log_level = log_level,
		.log_callback = (void *)log_call_func};

	if (fbe->init(conf) != 0)
	{
		std::cerr << "Falcon Behavior Engine init failed, please check configs..." << std::endl;
		return 1;
	}

	std::string report;
	if (!rule.empty())
	{
		report = fbe->rscan(scap_file, rule, true, filter_string, timeout, max_events_num);
	}
	else
	{
		report = fbe->scan(scap_file, evt_log_file, filter_string, timeout, max_events_num);
	}

	std::cout << "FBE_Report: " << report << std::endl;

	delete fbe;

	return 0;
}

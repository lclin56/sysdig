/*

*/
#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <chrono>
#ifndef _WIN32
#include <getopt.h>
#endif // _WIN32
#include <csignal>
#include <sinsp.h>
#include <functional>
#include <memory>
#include "util.h"
#include "filter/ppm_codes.h"
#include <unordered_set>
#include <memory>
#include <chisel.h>
#include "chisel_utils.h"
#include "chisel_fields_info.h"

#ifndef _WIN32
extern "C"
{
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
}
#endif // _WIN32

using namespace std;

// Functions used for dumping to stdout
void raw_dump(sinsp&, sinsp_evt* ev);
void formatted_dump(sinsp&, sinsp_evt* ev);

libsinsp::events::set<ppm_sc_code> extract_filter_sc_codes(sinsp& inspector);
std::function<void(sinsp&, sinsp_evt*)> dump = formatted_dump;
static bool g_interrupted = false;
static const uint8_t g_backoff_timeout_secs = 2;
static bool enable_glogger = false;
string filter_string = "";
string file_path = "";
static uint64_t max_events = UINT64_MAX;

string chisels_file = "";
std::vector<sinsp_chisel*> g_chisels;

sinsp_evt* get_event(sinsp& inspector, std::function<void(const std::string&)> handle_error);

#define EVENT_HEADER                                                                                                   \
	"%evt.num %evt.time cat=%evt.category container=%container.id proc=%proc.name(%proc.pid.%thread.tid) "
#define EVENT_TRAILER "%evt.dir %evt.type %evt.args"

#define EVENT_DEFAULTS EVENT_HEADER EVENT_TRAILER
#define PROCESS_DEFAULTS EVENT_HEADER "ppid=%proc.ppid exe=%proc.exe args=[%proc.cmdline] " EVENT_TRAILER

#define JSON_PROCESS_DEFAULTS                                                                                          \
	"*%evt.num %evt.time %evt.category %container.id %proc.ppid %proc.pid %evt.type %proc.exe %proc.cmdline "      \
	"%evt.args"

std::string default_output = EVENT_DEFAULTS;
std::string process_output = PROCESS_DEFAULTS;
std::string net_output = PROCESS_DEFAULTS " %fd.name";

static std::unique_ptr<sinsp_evt_formatter> default_formatter = nullptr;
static std::unique_ptr<sinsp_evt_formatter> process_formatter = nullptr;
static std::unique_ptr<sinsp_evt_formatter> net_formatter = nullptr;

static void sigint_handler(int signum) { g_interrupted = true; }

static void usage()
{
	string usage = R"(Usage: sinsp-example [options]

Overview: Goal of sinsp-example binary is to test and debug sinsp functionality and print events to STDOUT. All drivers are supported.

Options:
  -h, --help                                 Print this page.
  -f <filter>, --filter <filter>             Filter string for events (see https://falco.org/docs/rules/supported-fields/ for supported fields).
  -s <path>, --scap_file <path>              Scap file
  -n, --num-events                           Number of events to be retrieved (no limit by default)
  -g, --enable-glogger                       Enable libs g_logger, set to SEV_DEBUG. For a different severity adjust the test binary source and re-compile.
  -r, --raw                                  raw event ouput
  -c, --chiels                               file of chiels lists
)";
	cout << usage << endl;
}

#ifndef _WIN32
// Parse CLI options.
void parse_CLI_options(sinsp& inspector, int argc, char** argv)
{
	static struct option long_options[] = {{"help", no_argument, 0, 'h'},
					       {"filter", required_argument, 0, 'f'},
					       {"scap_file", required_argument, 0, 's'},
					       {"num-events", required_argument, 0, 'n'},
					       {"enable-glogger", no_argument, 0, 'g'},
					       {"raw", no_argument, 0, 'r'},
					       {"chiels", required_argument, 0, 'c'},
					       {0, 0, 0, 0}};

	bool format_set = false;
	int op;
	int long_index = 0;
	while((op = getopt_long(argc, argv, "hf:s:n:grc:", long_options, &long_index)) != -1)
	{
		switch(op)
		{
		case 'h':
			usage();
			exit(EXIT_SUCCESS);
		case 'f':
			filter_string = optarg;
			break;
		case 'j':
			dump = formatted_dump;
			if(!format_set)
			{
				default_output = DEFAULT_OUTPUT_STR;
				process_output = JSON_PROCESS_DEFAULTS;
				net_output = JSON_PROCESS_DEFAULTS " %fd.name";
			}
			inspector.set_buffer_format(sinsp_evt::PF_JSON);
			break;
		case 's':
			file_path = optarg;
			break;
		case 'n':
			max_events = std::atol(optarg);
			break;
		case 'g':
			enable_glogger = true;
			break;
		case 'r':
			dump = raw_dump;
			break;
		case 'c':
			chisels_file = optarg;
		default:
			break;
		}
	}
}
#endif // _WIN32

libsinsp::events::set<ppm_sc_code> extract_filter_sc_codes(sinsp& inspector)
{
	auto ast = inspector.get_filter_ast();
	if(ast != nullptr)
	{
		return libsinsp::filter::ast::ppm_sc_codes(ast.get());
	}

	return {};
}

static void free_chisels()
{
	for(auto& g_chisel : g_chisels)
	{
		delete g_chisel;
	}

	g_chisels.clear();
}

static void chisels_on_capture_start()
{
	for(auto& g_chisel : g_chisels)
	{
		g_chisel->on_capture_start();
	}
}

static void chisels_on_capture_end()
{
	for(auto& g_chisel : g_chisels)
	{
		g_chisel->on_capture_end();
	}
}

static void chisels_do_timeout(sinsp_evt* ev)
{
	for(std::vector<sinsp_chisel*>::iterator it = g_chisels.begin(); it != g_chisels.end(); ++it)
	{
		(*it)->do_timeout(ev);
	}
}

static void parse_chisel_args(sinsp_chisel* ch, std::shared_ptr<gen_event_filter_factory> filter_factory, int optind,
			      int argc, char** argv, int32_t* n_filterargs)
{
	uint32_t nargs = ch->get_n_args();
	uint32_t nreqargs = ch->get_n_required_args();
	std::string args;

	if(nargs != 0)
	{
		if(optind > (int32_t)argc)
		{
			throw sinsp_exception("invalid number of arguments for chisel " + std::string(optarg) + ", " +
					      std::to_string((long long int)nargs) + " expected.");
		}
		else if(optind < (int32_t)argc)
		{
			args = argv[optind];

			if(nreqargs != 0)
			{
				ch->set_args(args);
				(*n_filterargs)++;
			}
			else
			{
				if(args[0] != '-')
				{
					std::string testflt;

					for(int32_t j = optind; j < argc; j++)
					{
						testflt += argv[j];
						if(j < argc - 1)
						{
							testflt += " ";
						}
					}

					if(nargs == 1 && ch->get_lua_script_info()->m_args[0].m_type == "filter")
					{
						ch->set_args(args);
						(*n_filterargs)++;
					}
					else
					{
						try
						{
							sinsp_filter_compiler compiler(filter_factory, testflt);
							sinsp_filter* s = compiler.compile();
							delete s;
						}
						catch(...)
						{
							ch->set_args(args);
							(*n_filterargs)++;
						}
					}
				}
			}
		}
		else
		{
			if(nreqargs != 0)
			{
				throw sinsp_exception("missing arguments for chisel " + std::string(optarg));
			}
		}
	}
}

int load_chisels(sinsp& inspector, const std::string& chisels_file)
{
    std::ifstream file(chisels_file);
    std::string chisel_path;

    if (!file.is_open())
    {
        std::cerr << "Failed to open chisels file: " << chisels_file << std::endl;
        return -1; 
    }

    while (std::getline(file, chisel_path))
    {
        if (chisel_path.empty()) continue; 

        sinsp_chisel* ch = new sinsp_chisel(&inspector, chisel_path);

        // parse_chisel_args(ch, filter_factory, optind, argc, argv, &n_filterargs);

        ch->on_init();

        g_chisels.push_back(ch);
    }

    return true; 
}

//
// Sample filters:
//   "evt.category=process or evt.category=net"
//   "evt.dir=< and (evt.category=net or (evt.type=execveat or evt.type=execve or evt.type=clone or evt.type=fork or
//   evt.type=vfork))"
//
int main(int argc, char** argv)
{
	sinsp inspector;

#ifndef _WIN32
	parse_CLI_options(inspector, argc, argv);

	signal(SIGPIPE, sigint_handler);
#endif // _WIN32

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	if(enable_glogger)
	{
		std::cout << "-- Enabled g_logger.'" << std::endl;
		g_logger.set_severity(sinsp_logger::SEV_DEBUG);
		g_logger.add_stdout_log();
	}

	if(!filter_string.empty())
	{
		try
		{
			inspector.set_filter(filter_string);
		}
		catch(const sinsp_exception& e)
		{
			cerr << "[ERROR] Unable to set filter: " << e.what() << endl;
		}
	}

	if(file_path.empty())
	{
		return -1;
	}

	inspector.open_savefile(file_path);

	if()

		std::cout << "-- Start capture" << std::endl;

	inspector.start_capture();

	default_formatter = std::make_unique<sinsp_evt_formatter>(&inspector, default_output);
	process_formatter = std::make_unique<sinsp_evt_formatter>(&inspector, process_output);
	net_formatter = std::make_unique<sinsp_evt_formatter>(&inspector, net_output);

	std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
	uint64_t num_events = 0;
	while(!g_interrupted && num_events < max_events)
	{
		sinsp_evt* ev = get_event(inspector, [](const std::string& error_msg)
					  { cout << "[ERROR] " << error_msg << endl; });
		if(ev != nullptr)
		{
            for(std::vector<sinsp_chisel*>::iterator it = g_chisels.begin(); it != g_chisels.end(); ++it)
			{
				if((*it)->run(ev) == false)
				{
					continue;
				}
			}
		}
	}

	std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
	const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();

	inspector.stop_capture();

	std::cout << "-- Stop capture" << std::endl;
	std::cout << "Retrieved events: " << std::to_string(num_events) << std::endl;
	std::cout << "Time spent: " << duration << "ms" << std::endl;
	if(duration > 0)
	{
		std::cout << "Events/ms: " << num_events / (long double)duration << std::endl;
	}

	return 0;
}

sinsp_evt* get_event(sinsp& inspector, std::function<void(const std::string&)> handle_error)
{
	sinsp_evt* ev = nullptr;

	int32_t res = inspector.next(&ev);

	if(res == SCAP_SUCCESS)
	{
		return ev;
	}
	if(res == SCAP_EOF)
	{
		std::cout << "-- EOF" << std::endl;
		g_interrupted = true;
		return nullptr;
	}

	if(res != SCAP_TIMEOUT && res != SCAP_FILTERED_EVENT)
	{
		handle_error(inspector.getlasterr());
		std::this_thread::sleep_for(std::chrono::seconds(g_backoff_timeout_secs));
	}

	return nullptr;
}

void formatted_dump(sinsp&, sinsp_evt* ev)
{
	std::string output;
	if(ev->get_category() == EC_PROCESS)
	{
		process_formatter->tostring(ev, output);
	}
	else if(ev->get_category() == EC_NET || ev->get_category() == EC_IO_READ || ev->get_category() == EC_IO_WRITE)
	{
		net_formatter->tostring(ev, output);
	}
	else
	{
		default_formatter->tostring(ev, output);
	}

	cout << output << std::endl;
}

static void hexdump(const unsigned char* buf, size_t len)
{
	bool in_ascii = false;

	putc('[', stdout);
	for(size_t i = 0; i < len; ++i)
	{
		if(isprint(buf[i]))
		{
			if(!in_ascii)
			{
				in_ascii = true;
				if(i > 0)
				{
					putc(' ', stdout);
				}
				putc('"', stdout);
			}
			putc(buf[i], stdout);
		}
		else
		{
			if(in_ascii)
			{
				in_ascii = false;
				fputs("\" ", stdout);
			}
			else if(i > 0)
			{
				putc(' ', stdout);
			}
			printf("%02x", buf[i]);
		}
	}

	if(in_ascii)
	{
		putc('"', stdout);
	}
	putc(']', stdout);
}

void raw_dump(sinsp& inspector, sinsp_evt* ev)
{
	string date_time;
	sinsp_utils::ts_to_iso_8601(ev->get_ts(), &date_time);

	cout << "ts=" << date_time;
	cout << " tid=" << ev->get_tid();
	cout << " type=" << (ev->get_direction() == SCAP_ED_IN ? '>' : '<') << get_event_type_name(ev);
	cout << " category=" << get_event_category_name(ev->get_category());
	cout << " nparams=" << ev->get_num_params();

	for(size_t i = 0; i < ev->get_num_params(); ++i)
	{
		const sinsp_evt_param* p = ev->get_param(i);
		const struct ppm_param_info* pi = ev->get_param_info(i);
		cout << ' ' << i << ':' << pi->name << '=';
		hexdump((const unsigned char*)p->m_val, p->m_len);
	}

	cout << endl;
}


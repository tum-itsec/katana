#include <iostream>
#include <iterator>
#include <vector>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <string>
#include <sstream>
#include <set>
#include <map>
#include <unistd.h>


// This is the first gcc header to be included
#include "gcc-plugin.h"
#include "plugin.h"
#include "plugin-version.h"
#include "bversion.h"
#include "tree.h"
#include "tree-ssa-alias.h"
#include "basic-block.h"

#if BUILDING_GCC_VERSION >= 4009
#include "gimple-expr.h"
#endif

#include "gimple.h"

#include "cgraph.h"

#if BUILDING_GCC_VERSION >= 4009

#include "pass_manager.h"
#include "print-tree.h"
#include "gimple-iterator.h"
#include "gimple-walk.h"
#include "context.h"
#else
#include "tree-flow.h"
#endif

#if BUILDING_GCC_VERSION < 9000
#define TDF_NONE 0
#endif

#if BUILDING_GCC_VERSION < 4009
#define tree_to_uhwi(t) TREE_INT_CST_LOW(t)
#endif

#if BUILDING_GCC_VERSION >= 8000
#include "stringpool.h"
#endif

#include "tree-pass.h"
#include "gimple-pretty-print.h"

#if BUILDING_GCC_VERSION >= 4009
#include "attribs.h"
#endif

// We must assert that this plugin is GPL compatible
int plugin_is_GPL_compatible;

#if BUILDING_GCC_VERSION < 4009
#define get_tree_code_name(name) tree_code_name[name]
#endif


static bool flowana_debug = false;
#define ddebug(...) do { if(flowana_debug) { fprintf(stderr, "%s: ", __func__); fprintf(stderr, __VA_ARGS__); }} while(0);
#define ddebug_tree(tree) do { if(flowana_debug) { debug_tree(tree); }} while(0);
#define ddebug_gimple_stmt(stmt) do { if(flowana_debug) { print_gimple_stmt(stderr, stmt, 0, TDF_NONE); }} while(0);

struct ifdef_info {
	int depth;
	int blocknum;
};

struct field_element {
	std::string name;
	std::string type;
	int offset;
	int ifblknum;
};

static std::ofstream fout;
static std::map<tree, std::string> typemap;
static std::map<std::string, std::vector<ifdef_info>> ifdefmap_cache;
static std::set<tree> lazy_types;

static std::ostream& out_stream() {
	if(fout.is_open()) {
		return fout;
	} else {
		return std::cerr;
	}
}

// Stolen from StackOverflow
inline bool ends_with(std::string const & value, std::string const & ending)
{
    if (ending.size() > value.size()) return false;
    return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}

//static bool struct_modified_by_preprocessor(expanded_location loc) {
//	std::ifstream file;
//	file.open(loc.file, ios::in);
//	for(;;) {
//		char* buf = new char[1024];
//		ssize_t data_read = file.read(buf, 1024);	
//		if(strstr(buf, "#ifdef") 
//	}
//}

// copied from randomize_layout_plugin.c
static bool is_fptr(const_tree fieldtype)
{
	if (TREE_CODE(fieldtype) != POINTER_TYPE)
		return false;

	return TREE_CODE(TREE_TYPE(fieldtype)) == FUNCTION_TYPE;
}

// copied from randomize_layout_plugin.c
static const_tree get_field_type(const_tree field)
{
	return strip_array_types(TREE_TYPE(field));
}

// copied from randomize_layout_plugin.c
static int is_pure_ops_struct(const_tree node)
{
	const_tree field;

	gcc_assert(TREE_CODE(node) == RECORD_TYPE || TREE_CODE(node) == UNION_TYPE);

	for (field = TYPE_FIELDS(node); field; field = TREE_CHAIN(field)) {
		const_tree fieldtype = get_field_type(field);
		enum tree_code code = TREE_CODE(fieldtype);

		if (node == fieldtype)
			continue;

		if (code == RECORD_TYPE || code == UNION_TYPE) {
			if (!is_pure_ops_struct(fieldtype))
				return 0;
			continue;
		}

		if (!is_fptr(fieldtype))
			return 0;
	}

	return 1;
}

static std::vector<ifdef_info> get_ifdef_map(std::string filename) {
	std::ifstream f;
	std::vector<ifdef_info> ifdef_map;
	std::vector<std::string> lines;
	int depth = 0;
	int block = 0;
	f.open(filename);
	for(std::string str; std::getline(f, str);) {
		if(str.find("#if") != std::string::npos) {
			depth += 1;
			block += 1;
		}
		//out_stream() << "Depth: " << depth << " " << str << std::endl;
		lines.push_back(str);
		struct ifdef_info foo;
		foo.depth = depth;
		foo.blocknum = block;
		ifdef_map.push_back(foo);
		if(str.find("#endif") != std::string::npos) {
			depth -= 1;
			block += 1;
		}
	}
	//out_stream() << filename << " Depth: " << depth << std::endl;
	//if(depth != 0) {
	//	for(size_t i = 0; i < lines.size(); i++) {
	//		out_stream() << "Depth: " << ifdef_map[i].depth << " " << ifdef_map[i].blocknum << " " << lines[i] << std::endl;
	//	}
	//}
	return ifdef_map;
}

static std::vector<ifdef_info> get_ifdef_map_cached(std::string filename) {
	auto ifdefmap_it = ifdefmap_cache.find(filename);
	if(ifdefmap_it != ifdefmap_cache.end()) {
		return ifdefmap_it->second;
	} else {
		auto ifdefmap = get_ifdef_map(filename);
		ifdefmap_cache[filename] = ifdefmap;
		return ifdefmap;
	}
}

static std::string get_struct_name(tree arg) {
	std::string res = "???";
	if(TREE_TYPE(arg)) {
		if(TYPE_NAME(TREE_TYPE(arg)) && TREE_CODE(TYPE_NAME(TREE_TYPE(arg))) == IDENTIFIER_NODE) {
			// Handle simple named structs
			res = IDENTIFIER_POINTER(TYPE_NAME(TREE_TYPE(arg)));
		}
		else if (TYPE_MAIN_VARIANT(TREE_TYPE(arg)) && TYPE_NAME(TYPE_MAIN_VARIANT(TREE_TYPE(arg))) && TREE_CODE(TYPE_NAME(TYPE_MAIN_VARIANT(TREE_TYPE(arg)))) == IDENTIFIER_NODE)
		{
			// Handle named structs with typedef alias
			res = IDENTIFIER_POINTER(TYPE_NAME(TYPE_MAIN_VARIANT(TREE_TYPE(arg))));
		}
		else if (TYPE_NAME(TREE_TYPE(arg)) && TREE_CODE(TYPE_NAME(TREE_TYPE(arg))) == TYPE_DECL && DECL_NAME(TYPE_NAME(TREE_TYPE(arg))) && TREE_CODE(DECL_NAME(TYPE_NAME(TREE_TYPE(arg)))) == IDENTIFIER_NODE) {
			// Handle unnamed structs with typedef
			res = IDENTIFIER_POINTER(DECL_NAME(TYPE_NAME(TREE_TYPE(arg))));
		}
	}
	return res;
}

static std::vector<field_element> iter_fields(std::string parent_struct_type, tree struct_type, int base_offset, ifdef_info struct_start_blk, std::vector<ifdef_info> ifdefmap) {
	std::vector<field_element> results;
	bool randomized = false;
	if(lookup_attribute("randomize_layout", TYPE_ATTRIBUTES(TYPE_MAIN_VARIANT(struct_type)))) {
		randomized = true;
	}
	tree fields = TYPE_FIELDS(struct_type);
	for(tree f = fields; f != NULL; f = TREE_CHAIN(f)) {
		int offset = base_offset + tree_to_uhwi(DECL_FIELD_OFFSET(f)) + tree_to_uhwi(DECL_FIELD_BIT_OFFSET(f)) / 8;
		int ifdefblk = -1;
		if(DECL_SOURCE_LOCATION(f)) {
			auto loc = expand_location(DECL_SOURCE_LOCATION(f));
			auto curinfo = ifdefmap[loc.line - 1];
			ifdefblk = curinfo.blocknum - struct_start_blk.blocknum;
		}
		ifdefblk = randomized ? 999 : ifdefblk;
		std::string name = "???";
		if(DECL_NAME(f) != NULL && IDENTIFIER_POINTER(DECL_NAME(f))) {
			name = IDENTIFIER_POINTER(DECL_NAME(f));
			//fprintf(stderr, "> Struct: %s Field: %s Type: %s Offset: %d Blk: %d\n", parent_struct_type.c_str(), name.c_str(), get_tree_code_name(TREE_CODE(TREE_TYPE(f))), offset, ifdefblk);
			results.push_back({.name = name, .type = get_tree_code_name(TREE_CODE(TREE_TYPE(f))), .offset = offset, .ifblknum = ifdefblk});
		} else if(TREE_CODE(TREE_TYPE(f)) == UNION_TYPE || TREE_CODE(TREE_TYPE(f)) == RECORD_TYPE) {
			auto subres = iter_fields(parent_struct_type, TREE_TYPE(f), offset, struct_start_blk, ifdefmap);
			std::copy(subres.begin(), subres.end(), std::back_inserter(results));
		} else {
			//printf("> Struct: %s Field: %s Type: %s Offset: %d Blk: %d\n", parent_struct_type.c_str(), name.c_str(), get_tree_code_name(TREE_CODE(TREE_TYPE(f))), offset, -1);
			results.push_back({.name = name, .type = get_tree_code_name(TREE_CODE(TREE_TYPE(f))), .offset = offset, .ifblknum = -1});
		}
	}
	return results;
}

static void process_type(tree type) {
	if(type == NULL_TREE || TREE_CODE(type) != RECORD_TYPE) {
		return;
	}

	// Skip already visited types
	if(typemap.count(type) == 1) {
		return;
	}
	
	int count_fields = 0;
	for(tree f = TYPE_FIELDS(type); f != NULL; f = TREE_CHAIN(f)) {
		count_fields++;
	}

	// We are not interested in declarations
	if(count_fields == 0) {
		return;
	}

	std::stringstream type_name;
	std::vector<ifdef_info> ifdefmap;
	ifdef_info struct_start;
	std::string struct_type_name = get_struct_name(type);
	if(TYPE_NAME(type))
	{ 
		if(TREE_CODE(TYPE_NAME(type)) == IDENTIFIER_NODE)
		{
			type_name << "{ \"name\": \"" << IDENTIFIER_POINTER(TYPE_NAME(type)) << "\",";
			//type_name << " " << std::string(DECL_SOURCE_FILE(DECL_CHAIN(type))) << ":" << std::string(DECL_SOURCE_LINE(DECL_CHAIN(type))) << std::endl;
			//type_name << " " << std::string(DECL_SOURCE_FILE(DECL_CHAIN(type))) + ":" + std::to_string(DECL_SOURCE_LINE(DECL_CHAIN(type)));
			auto loc = DECL_SOURCE_LOCATION(DECL_CHAIN(type));
			auto loc2 = expand_location(loc); 
			//auto range = get_range_from_loc(line_table, loc);
			type_name << "\"loc\":\"" << loc2.file << ":" << loc2.line << "\", \"attributes\": [ ";
			if(lookup_attribute("randomize_layout", TYPE_ATTRIBUTES(type))) {
				type_name << "\"randomize_layout\",";
			}
			if(lookup_attribute("no_randomize_layout", TYPE_ATTRIBUTES(type))) {
				type_name << "\"no_randomize_layout\",";
			}
			if(is_pure_ops_struct(type)) {
				type_name << "\"pure_ops_struct\",";
			}
			type_name.seekp(-1,type_name.cur);
			type_name << "],";
			ifdefmap = get_ifdef_map_cached(loc2.file);
			struct_start = ifdefmap[loc2.line - 1];
		} else if(TREE_CODE(TYPE_NAME(type)) == TYPE_DECL && DECL_NAME(TYPE_NAME(type))) {
			type_name << IDENTIFIER_POINTER(DECL_NAME(TYPE_NAME(type)));
		} else {
			type_name << "???";
		}
		bool first_field = true;
		type_name << "\"fields\": ["; 
		auto field_info = iter_fields(IDENTIFIER_POINTER(TYPE_NAME(type)), type, 0, struct_start, ifdefmap);
		for(const auto& f : field_info) {
			if(!first_field) { type_name << ", ";}
			first_field = false;
			type_name << "{\"name\":\"" << f.name << "\",\"offset\":" << f.offset;
			type_name << ",\"ifdefblk\": " << f.ifblknum << "}";
		}
		type_name << "]}";
		typemap.insert({type, type_name.str()});
	}
}

static void finish_type(void* event_data, void* data) {
	tree type = (tree) event_data;
	
	// We havent been able to build the 3.10.108 using lazy evaluation of types
	// fallback to straight processing. As structure randomization is not used with such
	// old kernels, this does no harm.
#if BUILDING_GCC_VERSION >= 4009
	lazy_types.insert(type);
#else
	process_type(type);
#endif
}

static void gcc_end(void* event_data, void* data) {
	out_stream() << "[";
	bool first = true;
	for (auto it = lazy_types.begin(); it != lazy_types.end(); ++it) {
		process_type(*it);
	}
	for (auto it = typemap.begin(); it != typemap.end(); ++it) {
		//std::string type_name = IDENTIFIER_POINTER(DECL_NAME(TYPE_NAME(TREE_TYPE(*it))));
		if(!first) { out_stream() << "," << std::endl; }
		first = false;
		out_stream() << it->second;
		//for(tree f = TYPE_FIELDS(it->first); f != NULL; f = TREE_CHAIN(f)) {
		//	debug_tree(f);
		//}
	}
	out_stream() << "]";
}

static struct attribute_spec randomize_layout_attr = { };
static struct attribute_spec no_randomize_layout_attr = { };
static void register_attributes(void *event_data, void *data)
{
	randomize_layout_attr.name		= "randomize_layout";
	randomize_layout_attr.type_required	= true;
	randomize_layout_attr.handler		= NULL;
	randomize_layout_attr.affects_type_identity = true;

	no_randomize_layout_attr.name		= "no_randomize_layout";
	no_randomize_layout_attr.type_required	= true;
	no_randomize_layout_attr.handler	= NULL;
	no_randomize_layout_attr.affects_type_identity = true;

	register_attribute(&randomize_layout_attr);
	register_attribute(&no_randomize_layout_attr);
}

int plugin_init (struct plugin_name_args *plugin_info,
	     struct plugin_gcc_version *version)
{
  bool do_not_register_attributes = false;
  // We check the current gcc loading this plugin against the gcc we used to
  // created this plugin
  if (!plugin_default_version_check (version, &gcc_version))
    {
		std::cerr << "This GCC plugin is for version " << GCCPLUGIN_VERSION_MAJOR
	<< "." << GCCPLUGIN_VERSION_MINOR << "\n";
      return 1;
    }

  for(int i=0;i<plugin_info->argc;i++) {
	  if(strcmp(plugin_info->argv[i].key, "outdir") == 0) {
		  // Obtain our command line on the hacky way
		  std::ifstream procfile("/proc/self/cmdline", std::ios::in);
		  std::string outfile = std::to_string(getpid());
		  while(!procfile.eof()) {
			  std::string arg;
			  std::getline(procfile, arg, '\0');
			  if(ends_with(arg, ".c")) {
				  std::replace(arg.begin(), arg.end(), '/', '-');
				  outfile = arg;
				  break;
			  }
		  }

		  std::string outfile_path = std::string { plugin_info->argv[i].value } + "/" + outfile; // per-file output file to avoid race condition with parallel builds
		  fout.open(outfile_path);
	  }
	  if(strcmp(plugin_info->argv[i].key, "debug") == 0) {
		  flowana_debug = true;
	  }
	  if(strcmp(plugin_info->argv[i].key, "noregister") == 0) {
		  do_not_register_attributes = true;
	  }
  }

  register_callback(plugin_info->base_name, PLUGIN_FINISH_TYPE, finish_type, NULL);
  //register_callback(plugin_info->base_name, PLUGIN_FINISH_TYPE, finish_decl, NULL);
  register_callback(plugin_info->base_name, PLUGIN_FINISH, gcc_end, NULL);
  if(!do_not_register_attributes) { 
	  register_callback(plugin_info->base_name, PLUGIN_ATTRIBUTES, register_attributes, NULL);
  }

  return 0;
}

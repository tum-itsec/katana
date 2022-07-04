#include <iostream>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <string>
#include <sstream>
#include <set>
#include <unistd.h>


// This is the first gcc header to be included
#include "gcc-plugin.h"
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

#include "tree-pass.h"
#include "gimple-pretty-print.h"

// We must assert that this plugin is GPL compatible
int plugin_is_GPL_compatible;

static int calls_so_far;
static int bbs_so_far;
static bool flowana_debug = false;
#define ddebug(...) do { if(flowana_debug) { fprintf(stderr, "%s: ", __func__); fprintf(stderr, __VA_ARGS__); }} while(0);
#define ddebug_tree(tree) do { if(flowana_debug) { debug_tree(tree); }} while(0);
#define ddebug_gimple_stmt(stmt) do { if(flowana_debug) { print_gimple_stmt(stderr, stmt, 0, TDF_NONE); }} while(0);

#define IS_GLOBAL(t)  (TREE_STATIC(t) || DECL_EXTERNAL(t) || TREE_PUBLIC(t))

static std::ofstream fout;

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

inline bool starts_with(std::string const & value, std::string const & start)
{
	if (start.size() > value.size()) return false;
	return std::equal(start.begin(), start.end(), value.begin());
}

static bool needs_lifting(tree arg0) {
	return TREE_CODE(arg0) == COMPONENT_REF &&
				TREE_CODE(TREE_OPERAND(arg0, 1)) == FIELD_DECL &&
				!DECL_NAME(TREE_OPERAND(arg0, 1));
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

static std::string stringify_access_ex(tree orig_type, tree arg);
static std::string trace_member_of(tree container, int offset, tree type) {
	ddebug("<BEGIN TRACE>\n");
	ddebug_tree(container);
	ddebug_tree(type);
	if (TREE_CODE(container) == POINTER_TYPE)
		return "";
	for (tree field = TYPE_FIELDS(container); field; field = TREE_CHAIN(field)) {
		if (TREE_CODE(field) != FIELD_DECL)
			continue;
		int byte_offset = DECL_FIELD_OFFSET(field) ? tree_to_uhwi(DECL_FIELD_OFFSET(field)) : 0;
		int bit_offset = DECL_FIELD_BIT_OFFSET(field) ? tree_to_uhwi(DECL_FIELD_BIT_OFFSET(field)) : 0;
		int field_offset = byte_offset * BITS_PER_UNIT + bit_offset;
		int field_size = DECL_SIZE(field) ? tree_to_uhwi(DECL_SIZE(field)) : 0;
		if (!field_size)
			field_size = DECL_SIZE_UNIT(field) ? tree_to_uhwi(DECL_SIZE_UNIT(field)) * BITS_PER_UNIT : 0;
		if (!field_size)
			continue;
		ddebug("Checking member: %s %#x[+%#x]\n", DECL_NAME(field) ? IDENTIFIER_POINTER(DECL_NAME(field)) : "<noname>", field_offset, field_size);
		if (field_offset <= offset && field_offset + field_size > offset) {
			ddebug("Found candidate member: %s\n", DECL_NAME(field) ? IDENTIFIER_POINTER(DECL_NAME(field)) : "<noname>");
			ddebug("Field main variant:\n");
			ddebug_tree(TYPE_MAIN_VARIANT(TREE_TYPE(field)));
			ddebug("Target main variant:\n");
			ddebug_tree(TYPE_MAIN_VARIANT(type));
			bool same_type = (TREE_TYPE(field) == type || (TYPE_MAIN_VARIANT(TREE_TYPE(field)) && TYPE_MAIN_VARIANT(type) && TYPE_MAIN_VARIANT(TREE_TYPE(field)) == TYPE_MAIN_VARIANT(type)));
			if (field_offset == offset && same_type) {
				ddebug("<END TRACE>\n");
				return "." + stringify_access_ex(field, field);
			} else {
				std::string result = trace_member_of(TREE_TYPE(field), offset - field_offset, type);
				if (result.size()) {
					ddebug("<END TRACE>\n");
					return "." + stringify_access_ex(field, field) + result;
				}
			}
		}
	}
	ddebug("<END TRACE FAIL>\n");
	return "";
}
static void stringify_access_ex_int(tree orig_type, tree arg, std::stringstream &str) {
	ddebug("Stringify access Str: %s Arg:\n", str.str().c_str());
	if(TREE_CODE(arg) == MEM_REF) {
		tree arg0 = TREE_OPERAND(arg, 0);
		tree arg1 = TREE_OPERAND(arg, 1);

		// Sanity check if the displacement in arg1 is zero
		// if so, this is most likely the * Part of (*t).m which we handle
		// in COMPONENT_REF below
		// Check if arg0 has the same type as the mem_ref

		tree arg0_type = TREE_TYPE(arg0);
		tree mr_type = TREE_TYPE(arg);
		while (TREE_CODE(arg0_type) == POINTER_TYPE)
			arg0_type = TREE_TYPE(arg0_type);
		while (TREE_CODE(mr_type) == POINTER_TYPE)
			mr_type = TREE_TYPE(mr_type);
		if(TREE_CODE(arg1) == INTEGER_CST && 0 == compare_tree_int(arg1, 0)) {
			// Check for special case of implicit pointer cast for member at offset 0
			// TODO: See if we can merge this with the other trace_member_of stuff
			if (arg0_type == mr_type)
				stringify_access_ex_int(orig_type, arg0, str);
			else
				stringify_access_ex_int(arg, arg0, str);
		} else if (TREE_CODE(arg1) == INTEGER_CST && arg0_type != mr_type) {
			// Find member of type mr_type at this offset in arg0_type.
			int offset = tree_to_uhwi(arg1) * BITS_PER_UNIT;
			stringify_access_ex_int(arg0, arg0, str);
			std::string traced = trace_member_of(arg0_type, offset, mr_type);
			if (traced.size())
				str << traced;
			else
				str << ".???";
		} else {
		}
	} else if (TREE_CODE(arg) == COMPONENT_REF) {
		tree arg0 = TREE_OPERAND(arg, 0);
		tree arg1 = TREE_OPERAND(arg, 1);

		while(needs_lifting(arg0)) {
			arg0 = TREE_OPERAND(arg0, 0);
		}

		stringify_access_ex_int(orig_type, arg0, str);
		if (str.tellp() == 0)
			str << "???";
		str << ((TREE_CODE(arg0) == MEM_REF) ? "->" : ".");
		stringify_access_ex_int(orig_type, arg1, str);
	} else if(TREE_CODE(arg) == FIELD_DECL) {
		if (DECL_NAME(arg) && TREE_CODE(DECL_NAME(arg)) == IDENTIFIER_NODE) {
			str << IDENTIFIER_POINTER(DECL_NAME(arg));
		} else {
			str << "???";
		}
		std::string tmp = get_struct_name(arg);
		std::replace(tmp.begin(), tmp.end(), ' ', '_');
		str << "[" << tmp << "]";
	} else if(TREE_TYPE(arg)) {
		// Bugfix: If the arg variable is followed to by ssa, the the type
		// might be different due to casting
		// allow overwritting by using orig_type if set
		//fprintf(stderr, "Arg+++++++\n");
		//debug_tree(arg);
		//
		//Temporarly commented out, as this causes errornous output such as
		// unix_peer_get() -> call refcount_inc sock_common->__sk_common[sock_common].skc_refcnt[refcount_struct] 1
		if(orig_type != nullptr && TREE_TYPE(orig_type)) {
			arg = orig_type;
		}

		// Get rid of pointers before the record type
		while(TREE_CODE(TREE_TYPE(arg)) == POINTER_TYPE) {
			arg = TREE_TYPE(arg);
		}
		//fprintf(stderr, "Orig+++++++\n");
		//debug_tree(orig_type);
		//fprintf(stderr, "Final+++++++\n");
		//debug_tree(arg);
		//fprintf(stderr, "+++++++\n");
		str << get_struct_name(arg);
	}
}

static std::string stringify_access_ex(tree orig_type, tree arg) {
	std::stringstream res;
	stringify_access_ex_int(orig_type, arg, res);
	return res.str();
}

static std::string stringify_access_ex(tree arg) {
	std::stringstream res;
	stringify_access_ex_int(nullptr, arg, res);
	return res.str();
}

static std::set<void*> visited;

#if BUILDING_GCC_VERSION >= 6000
using gimple_fuck = gimple*;
#else
using gimple_fuck = gimple;
#endif

static tree follow_dataflow_to_global(gimple_fuck ssa_def) {
	if(visited.find(ssa_def) != visited.end()) {
		// Abort if we have already visited this tree node
		return NULL;
	}
	visited.insert(ssa_def);
	if(is_gimple_assign(ssa_def))
	{
		//std::cerr << "Assign Node" << std::endl;
		//debug_tree(SSA_NAME_DEF_STMT(gimple_assign_rhs1(ssa_def));
		tree rhs = gimple_assign_rhs1(ssa_def);
		//debug(ssa_def);
		//debug_tree(rhs);
		if(TREE_CODE(rhs) == VAR_DECL && IS_GLOBAL(rhs)) {
			return rhs;
		} else if(TREE_CODE(rhs) == ADDR_EXPR) {
			tree op1 = TREE_OPERAND(rhs, 0);
			if(TREE_CODE(op1) == VAR_DECL && IS_GLOBAL(op1)) {
				return op1;
			}
		}
	} else if(gimple_code(ssa_def) == GIMPLE_PHI) {
		// Follow all incoming dataflows to check for data of a
		// global symbol
		//std::cerr << "Phi Node" << std::endl;
		//std::cerr << "Arg 0" << std::endl;
		//debug_tree(arg0);
		//std::cerr << "Arg 1" << std::endl;
		//debug_tree(arg1);

		int n = gimple_phi_num_args(ssa_def);
		for(int i=0;i<n;i++) {
			//std::cerr << "I:" << i << std::endl;
			tree phi_arg = gimple_phi_arg_def(ssa_def, i);
			if(TREE_CODE(phi_arg) == SSA_NAME) {
				gimple_fuck ssa_def_arg = SSA_NAME_DEF_STMT(phi_arg);
				if(ssa_def_arg != NULL) {
					tree res = follow_dataflow_to_global(ssa_def_arg);
					if(res != NULL)
						return res;
				}
			}
			//debug_tree(parent);
			//std::cerr << gimple_code_name[gimple_code(SSA_NAME_DEF_STMT(parent))] << std::endl;
			//debug(SSA_NAME_DEF_STMT(parent));
			//debug_tree(gimple_assign_rhs1(SSA_NAME_DEF_STMT(parent)));
		}
	}
	return NULL;
}

static tree get_global_arg(tree arg)
{
	if(TREE_CODE(arg) == SSA_NAME && SSA_NAME_DEF_STMT(arg))
		return follow_dataflow_to_global(SSA_NAME_DEF_STMT(arg));
	else if(TREE_CODE(arg) == ADDR_EXPR)
		return get_global_arg(TREE_OPERAND(arg, 0));
	else if(TREE_CODE(arg) == VAR_DECL && IS_GLOBAL(arg))
		return arg;
	else
		return NULL;
}

static std::string get_symbol_name(tree arg) {
	std::string symbol_name = "???";
	if(DECL_NAME(arg) && TREE_CODE(DECL_NAME(arg)) == IDENTIFIER_NODE) {
		symbol_name = IDENTIFIER_POINTER(DECL_NAME(arg));
	}
	return symbol_name;
}

static bool gimple_finished = false;

static tree op_walk(tree* data, int* st, void* user) {
	tree res = NULL;
	if(gimple_finished) {
		//Exit early
		return NULL;
	}

	//ddebug_tree(*data);
	//debug("=======\n");
	if(TREE_CODE(*data) == COMPONENT_REF)
	{
		ddebug("Found COMPONENT_REF\n");
		tree arg0 = TREE_OPERAND(*data, 0);

		// This is an access in the form x->y.z or x.y.z
		// Currently, we will only lift anonymous members up
		// Test on task_struct->tasks with randomization whether this works.

		//std::string loc = "Unknown location";
		//if (cfun->decl && DECL_SOURCE_FILE(cfun->decl))
		//	loc = std::string(DECL_SOURCE_FILE(cfun->decl)) + ":" + std::to_string(DECL_SOURCE_LINE(cfun->decl));
		//fprintf(stderr, "++++++++ %s %s ++++++++\n", loc.c_str(), function_name(cfun));
		//debug_tree(arg0);
		//fprintf(stderr, " *** data *** \n");
		//debug_tree(*data);
		while(needs_lifting(arg0)) {
			arg0 = TREE_OPERAND(arg0,0);
			ddebug("Lifted anonymous component ref!\n");
		}

		//This is not a nested struct access
		if(TREE_CODE(TREE_TYPE(arg0)) == RECORD_TYPE)
		{
			ddebug("Arg0 in Component Ref is Record type\n");

			while(TREE_CODE(arg0) == COMPONENT_REF || TREE_CODE(arg0) == MEM_REF) {
				ddebug("Walking down nested component and mem_refs\n");
				arg0 = TREE_OPERAND(arg0, 0);
			}

			tree arg0_orig = arg0;

			// Okay cool... We found a record access
			// Step 1: Check for globals
			// Easy case: We do not have pointer access
			if(TREE_CODE(arg0) == VAR_DECL && IS_GLOBAL(arg0))
			{
				out_stream() << " global_access " << (TREE_PUBLIC(arg0) ? "public" : "private") << " " << get_symbol_name(arg0) << " " << stringify_access_ex(*data) << " " << calls_so_far << std::endl;
				res = arg0;
			}

			if(TREE_CODE(arg0) == SSA_NAME)
			{
				ddebug("Is SSA_NAME!\n");
				// Check if we end up in a global pointer
				gimple_fuck ssa_def = SSA_NAME_DEF_STMT(arg0);

				visited.clear();
				tree glob = follow_dataflow_to_global(ssa_def);
				if(glob != NULL && IS_GLOBAL(glob)) {
					out_stream() << " global_access " << (TREE_PUBLIC(glob) ? "public" : "private") << " " << get_symbol_name(glob) << " " << stringify_access_ex(*data) << " " << calls_so_far << std::endl;
					res = arg0;
				}

				// Check if we are comming from a function argument
				if(SSA_NAME_VAR(arg0)) {
					ddebug("Is SSA_NAME_VAR!\n");
					tree name_var = SSA_NAME_VAR(arg0);
					ddebug_tree(name_var);
					if(TREE_CODE(name_var) == PARM_DECL) {
						int n = 0;
						for(tree i = DECL_ARGUMENTS(DECL_CONTEXT(name_var)); i; i = DECL_CHAIN(i)) {
							if(name_var == i) {
								out_stream() << " param_access " << n << " " << stringify_access_ex(arg0_orig, *data) << " " << calls_so_far << std::endl;
								res = arg0;
							}
							n++;
						}
					}
				}

				// Check if this is the return value of a function
				tree bt = arg0;
				while(TREE_CODE(bt) == SSA_NAME && SSA_NAME_DEF_STMT(bt)
						&& is_gimple_assign(SSA_NAME_DEF_STMT(bt))
						&& (gimple_assign_single_p(SSA_NAME_DEF_STMT(bt)) || gimple_assign_cast_p(SSA_NAME_DEF_STMT(bt)))
						)
				{
					bt = gimple_assign_rhs1(SSA_NAME_DEF_STMT(bt));
				}

				if(TREE_CODE(bt) == SSA_NAME && SSA_NAME_DEF_STMT(bt))
				{
					if(gimple_code(SSA_NAME_DEF_STMT(bt)) == GIMPLE_CALL) {
						tree fndecl = gimple_call_fndecl(SSA_NAME_DEF_STMT(bt));
						std::string func_name = "???";
						if(fndecl && DECL_NAME(fndecl) && TREE_CODE(DECL_NAME(fndecl)) == IDENTIFIER_NODE) {
							func_name = std::string(IDENTIFIER_POINTER(DECL_NAME(fndecl)));
						}
						out_stream() << " retval_from_call " << func_name << " " << stringify_access_ex(arg0_orig, *data) << " " << calls_so_far << std::endl;
						res = arg0;
					} else if(gimple_code(SSA_NAME_DEF_STMT(bt)) == GIMPLE_ASM) {
#if BUILDING_GCC_VERSION >= 4009
						gasm *asm_stmt = as_a <gasm *> (SSA_NAME_DEF_STMT(bt));
#else
						gimple_fuck asm_stmt = SSA_NAME_DEF_STMT(bt);
#endif
						std::string asm_code = gimple_asm_string(asm_stmt);
						if(asm_code.find("%%gs") != std::string::npos && starts_with(asm_code, "mov")) {
							//fprintf(stderr, "Found asm\n");
							//debug_gimple_stmt(SSA_NAME_DEF_STMT(bt));
							out_stream() << " val_from_asm " << stringify_access_ex(*data)<< " " << calls_so_far << std::endl;
							res = arg0;
						}
					}
				}

			}
		}
	}
	// Ugly hack as gcc 5 terminates processing of the whole func/bb (?) on return != NULL
	if(res != NULL) {
		gimple_finished = true;
	}
	//return res;
	return NULL;
}

static void print_if_public(tree t) {
	if (!t)
		return;

	if(TREE_CODE(t) == ADDR_EXPR) {
		t = TREE_OPERAND(t, 0);
	}

	std::string name = "???";
	std::string type = "???";
	std::string type_ptr_postfix = "";
	tree ttype = TREE_TYPE(t);
	if (!ttype) {
		return;
	}
	while (ttype && TREE_CODE(t) == ARRAY_REF && TREE_CODE(TREE_OPERAND(t, 1)) != INTEGER_CST && (TREE_CODE(ttype) == ARRAY_TYPE || POINTER_TYPE_P(ttype))) {
		// resolve non-constant array access into global: strip array_ref + array_type
		t = TREE_OPERAND(t, 0);
		ttype = TREE_TYPE(ttype);
	}
	if(TREE_CODE(t) == VAR_DECL) {
		name = get_symbol_name(t);
	}
	while(ttype && POINTER_TYPE_P(ttype)) {
		type_ptr_postfix += "*";
		ttype = TREE_TYPE(ttype);
	}
	if(ttype && TYPE_NAME(ttype)) {
		if (TREE_CODE(TYPE_NAME(ttype)) == IDENTIFIER_NODE) {
			type = std::string(IDENTIFIER_POINTER(TYPE_NAME(ttype))) + type_ptr_postfix;
		} else if (TREE_CODE(TYPE_NAME(ttype)) == TYPE_DECL && DECL_NAME(TYPE_NAME(ttype)) && TREE_CODE(DECL_NAME(TYPE_NAME(ttype))) == IDENTIFIER_NODE) {
			// probably some built-in type/typedef we are not normally interested in,
			// but for globals we are!
			type = std::string(IDENTIFIER_POINTER(DECL_NAME(TYPE_NAME(ttype)))) + type_ptr_postfix;
		}
		std::replace(type.begin(), type.end(), ' ', '_');
	}
	if (name != "???" && type != "???" && IS_GLOBAL(t)) {
		out_stream() << " global_var " << (TREE_PUBLIC(t) ? "public" : "private") <<  " " << name << " " << type << " " << calls_so_far << std::endl;
	}
}

static void check_container_of(gimple_fuck gs) {
	// Special case to try and detect container_of()
	// Match rhs to SSA(__mptr) + <negative value>
	tree lhs = gimple_assign_lhs(gs);
	tree rhs = gimple_assign_rhs1(gs);
	tree rhs2 = gimple_assign_rhs2(gs);
	if (!lhs || !rhs || !rhs2)
		return;
	if (gimple_assign_rhs_code(gs) != POINTER_PLUS_EXPR)
		return;
	if (TREE_CODE(rhs) != SSA_NAME || TREE_CODE(rhs2) != INTEGER_CST)
		return;
	rhs = SSA_NAME_VAR(rhs);
	if (!rhs || !DECL_NAME(rhs) || TREE_CODE(DECL_NAME(rhs)) != IDENTIFIER_NODE)
		return;
	std::string name = IDENTIFIER_POINTER(DECL_NAME(rhs));
	if (name != "__mptr")
		return;
	intmax_t value = static_cast<intmax_t>(tree_to_uhwi(rhs2));
	if (value >= 0)
		return;
	tree lhs_type = TREE_TYPE(lhs); // if this is container_of, pointer to struct
	if (!lhs_type || !POINTER_TYPE_P(lhs_type))
		return;
	lhs_type = TREE_TYPE(lhs_type);
	if (!lhs_type || TREE_CODE(lhs_type) != RECORD_TYPE)
		return;
	// grab the name, and the correct field
	if (!TYPE_NAME(lhs_type) || TREE_CODE(TYPE_NAME(lhs_type)) != IDENTIFIER_NODE)
		return;
	std::string type_name = IDENTIFIER_POINTER(TYPE_NAME(lhs_type));

	uintmax_t target = static_cast<uintmax_t>(-value) * 8;
	uintmax_t bit_offset, bit_size;
	for (tree field = TYPE_FIELDS(lhs_type); field; field = TREE_CHAIN(field)) {
		//debug_tree(field);
		if (!DECL_FIELD_OFFSET(field) || TREE_CODE(DECL_FIELD_OFFSET(field)) != INTEGER_CST)
			continue;
		if (!DECL_FIELD_BIT_OFFSET(field) || TREE_CODE(DECL_FIELD_BIT_OFFSET(field)) != INTEGER_CST)
			continue;
		if (!TREE_TYPE(field) || !TYPE_SIZE(TREE_TYPE(field)) || TREE_CODE(TYPE_SIZE(TREE_TYPE(field))) != INTEGER_CST)
			continue;
		if (!DECL_NAME(field) || TREE_CODE(DECL_NAME(field)) != IDENTIFIER_NODE)
			continue;
		bit_offset = 8 * tree_to_uhwi(DECL_FIELD_OFFSET(field)) + tree_to_uhwi(DECL_FIELD_BIT_OFFSET(field));
		bit_size = tree_to_uhwi(TYPE_SIZE(TREE_TYPE(field)));
		name = IDENTIFIER_POINTER(DECL_NAME(field));
		if (bit_size == 0)
			continue; // skip empty members

		//out_stream() << " -> " << name << ": " << (bit_offset/8) << "	(" << (target/8) << ")\n";
		if (bit_offset == target)
			goto found_field;
	}
	return;

found_field:
	// @ [type_name]->[field_name] [bb]
	out_stream() << " container_of " << type_name << "->" << name << " " << calls_so_far << std::endl;
}

static tree gimple_walk(gimple_stmt_iterator* iter, bool* abort, struct walk_stmt_info* info) {
	gimple_fuck gs = gsi_stmt(*iter);
	if(flowana_debug) {
		fprintf(stderr, "========\n");
		print_gimple_stmt(stderr, gs, 0, TDF_LINENO);
	}

	// New gimple statement -> reset finished var
	gimple_finished = false;

	if(is_gimple_assign(gs)) {
		tree rhs = gimple_assign_rhs1(gs);
		print_if_public(rhs);
		tree lhs = gimple_assign_lhs(gs);
		print_if_public(lhs);

		check_container_of(gs);
	}

	if(gimple_code(gs) == GIMPLE_CALL) {
		std::stringstream buf;
		tree t = gimple_call_fndecl(gs);
		std::string func_name = "???";
		if(t && DECL_NAME(t) && TREE_CODE(DECL_NAME(t)) == IDENTIFIER_NODE) {
			func_name = std::string(IDENTIFIER_POINTER(DECL_NAME(t)));

			buf << " call " << func_name << " ";
			//printf("Args %d\n", gimple_call_num_args(gs));
		} else {
			/* buf << " call " << func_name << " "; */
			/* debug_tree(gimple_call_fn(gs)); */
			tree indfn = gimple_call_fn(gs);
			if (indfn) {
				tree rhs = indfn;
				while(TREE_CODE(indfn) == SSA_NAME && SSA_NAME_DEF_STMT(indfn) && is_gimple_assign(SSA_NAME_DEF_STMT(indfn)))
				{
					ddebug("Step: ");
					ddebug_gimple_stmt(SSA_NAME_DEF_STMT(indfn));
					rhs = gimple_assign_rhs1(SSA_NAME_DEF_STMT(indfn));
					//debug_tree(gimple_assign_rhs3(SSA_NAME_DEF_STMT(arg)));
					//print_gimple_stmt(stderr, SSA_NAME_DEF_STMT(arg), 0, TDF_ALL_VALUES);
					if(TREE_CODE(rhs) == ADDR_EXPR) {
						rhs = TREE_OPERAND(rhs, 0);
					}
					// Unsure if gimple_assign_single_p is sane here, but no checking leads
					// to walking over additions and so on...
					if(TREE_CODE(rhs) != SSA_NAME && !(gimple_assign_single_p(SSA_NAME_DEF_STMT(indfn)) && gimple_assign_cast_p(SSA_NAME_DEF_STMT(indfn)))) {
						break;
					}
					indfn = rhs;
				}
				if(TREE_CODE(rhs) == COMPONENT_REF) {
					//printf("%s\n", stringify_access_ex(rhs).c_str());
					tree arg0 = TREE_OPERAND(rhs, 0);
					while(needs_lifting(arg0)) {
						arg0 = TREE_OPERAND(arg0, 0);
					}
					/* tree arg1 = TREE_OPERAND(rhs, 1); */
					//debug_tree(rhs);

					// Seems to causes problems with unix_peer_get: call refcount_inc
					//func_name = stringify_access_ex(arg0, rhs);
					func_name = stringify_access_ex(rhs);
				}
			}
			buf << " call_indirect " << func_name << " ";
		}
		for(unsigned int i=0;i<gimple_call_num_args(gs);i++) {
			ddebug("Checking Arg %d for struct access\n", i);
			tree arg = gimple_call_arg(gs, i);
			print_if_public(arg);
			std::string arg_desc = "_";
			//if(func_name == "printk") {
			//	std::cerr << i << std::endl;
			//	debug_tree(arg);
			//}
			tree global_arg = get_global_arg(arg);
			if (global_arg && DECL_NAME(global_arg) && TREE_CODE(DECL_NAME(global_arg)) == IDENTIFIER_NODE) {
				arg_desc = std::string("#") + IDENTIFIER_POINTER(DECL_NAME(global_arg));
			} else {
				ddebug("Following dataflow back\n");
				tree rhs;
				// Traverse through SSA to defining statement
				while(TREE_CODE(arg) == SSA_NAME && SSA_NAME_DEF_STMT(arg) && is_gimple_assign(SSA_NAME_DEF_STMT(arg)))
				{
					ddebug("Step: ");
					ddebug_gimple_stmt(SSA_NAME_DEF_STMT(arg));
					rhs = gimple_assign_rhs1(SSA_NAME_DEF_STMT(arg));
					//debug_tree(gimple_assign_rhs3(SSA_NAME_DEF_STMT(arg)));
					//print_gimple_stmt(stderr, SSA_NAME_DEF_STMT(arg), 0, TDF_ALL_VALUES);
					if(TREE_CODE(rhs) == ADDR_EXPR) {
						rhs = TREE_OPERAND(rhs, 0);
					}
					// Unsure if gimple_assign_single_p is sane here, but no checking leads
					// to walking over additions and so on...
					if(TREE_CODE(rhs) != SSA_NAME && !(gimple_assign_single_p(SSA_NAME_DEF_STMT(arg)) && gimple_assign_cast_p(SSA_NAME_DEF_STMT(arg)))) {
						if(TREE_CODE(rhs) == COMPONENT_REF) {
							//printf("%s\n", stringify_access_ex(rhs).c_str());
							tree arg0 = TREE_OPERAND(rhs, 0);
							while(needs_lifting(arg0)) {
								ddebug("Lifting");
								arg0 = TREE_OPERAND(arg0, 0);
							}
							/* tree arg1 = TREE_OPERAND(rhs, 1); */
							//debug_tree(rhs);
							ddebug_tree(arg0);
							ddebug_tree(rhs);
							// Seems to causes problems with unix_peer_get: call refcount_inc
							//arg_desc = stringify_access_ex(arg0, rhs);

							arg_desc = stringify_access_ex(rhs);
						}
						break;
					}
					arg = rhs;
				}
			}
			buf << arg_desc << " ";
		}
		buf << calls_so_far;
		out_stream() << buf.str() << std::endl;

		//printf("LHS\n");
		//t = gimple_get_lhs(gs);
		//debug_tree(t);
		calls_so_far++;
	} else if(gimple_code(gs) == GIMPLE_RETURN) {
		ddebug("Checking Return Value backwards for struct access\n");
#if BUILDING_GCC_VERSION >= 4009
		greturn *ret_stmt = as_a<greturn *>(gs);
#else
		gimple_fuck ret_stmt = gs;
#endif
		tree i = gimple_return_retval(ret_stmt);

		while(i && TREE_CODE(i) == SSA_NAME
				&& SSA_NAME_DEF_STMT(i)
				&& is_gimple_assign(SSA_NAME_DEF_STMT(i))
				)
		{
			ddebug("Step: ");
			ddebug_gimple_stmt(SSA_NAME_DEF_STMT(i));
			tree rhs = gimple_assign_rhs1(SSA_NAME_DEF_STMT(i));

			if(TREE_CODE(rhs) != SSA_NAME
					&& !(gimple_assign_single_p(SSA_NAME_DEF_STMT(i)) && gimple_assign_cast_p(SSA_NAME_DEF_STMT(i)))
					)
			{
				if(TREE_CODE(rhs) == COMPONENT_REF)
				{
					out_stream() << " retval_from_access " << stringify_access_ex(rhs) << std::endl;
				}
			}
			i = rhs;
		}

	}
	//debug(gs);
	//out_stream() << gimple_code_name[gimple_code(gs)] << gimple_bb(gs)->index << std::endl;
	return NULL;
}

unsigned int do_stuff() {
	basic_block bb;
	std::string loc = "???";

	//cgraph_node::debug_cgraph();

	calls_so_far = 0;
	bbs_so_far = 0;
	if(DECL_SOURCE_LOCATION(cfun->decl)) {
		loc = std::string(DECL_SOURCE_FILE(cfun->decl)) + ":" + std::to_string(DECL_SOURCE_LINE(cfun->decl));
	}
	out_stream() << function_name(cfun) << "() " << loc << (TREE_PUBLIC(cfun->decl) ? "" : " [static]") << "\n";
	FOR_ALL_BB_FN(bb, cfun) {

		gimple_bb_info *bb_info = &bb->il.gimple;
		//debug_gimple_seq(bb_info->seq);

		//if(std::string(function_name(cfun)) == "chroot_fs_refs") {
		//	std::cerr << "BB" << bb->index << std::endl;
		//	//std::cerr << gimple_code_name[gimple_code(gs)] << std::endl;
		//	debug_gimple_seq(bb_info->seq);
		//}

		struct walk_stmt_info wi;
		memset(&wi, 0, sizeof(wi));
		walk_gimple_seq(bb_info->seq, gimple_walk, op_walk, &wi);
		bbs_so_far++;
		//if(std::string(function_name(cfun)) == "chroot_fs_refs") {
		//	std::cerr << "Next BB" << bb->next_bb->index << std::endl;
		//}
	}
	return 0;
}

#if BUILDING_GCC_VERSION >= 4009
namespace {
const pass_data flow_pass_data =
{
	GIMPLE_PASS,
	"flow_pass",	/* name */
	OPTGROUP_NONE,	/* optinfo_flags */
	TV_NONE,		/* tv_id */
	PROP_gimple_any,	/* properties_required */
	0,			/* properties_provided */
	0,			/* properties_destroyed */
	0,			/* todo_flags_start */
	0			/* todo_flags_finish */
};
}

struct flow_pass : gimple_opt_pass
{
	flow_pass(gcc::context * ctx) :
		gimple_opt_pass(flow_pass_data, ctx)
	{
	}

	virtual unsigned int execute(function * fun) override {
		return do_stuff();
	}
};
#else
static struct gimple_opt_pass flow_pass =
{
	{
	GIMPLE_PASS,
	"flow_pass",	/* name */
	OPTGROUP_NONE,			/* optinfo_flags */
	NULL,					 /* gate */
	do_stuff,				 /* execute */
	NULL,					 /* sub */
	NULL,					 /* next */
	0,						/* static_pass_number */
	TV_NONE,					/* tv_id */
	PROP_gimple_any,	 		/* properties_required */
	0,						/* properties_provided */
	0,						/* properties_destroyed */
	0,						/* todo_flags_start */
	0							/* todo_flags_finish */
	}
};

#endif


int plugin_init (struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
	// We check the current gcc loading this plugin against the gcc we used to
	// created this plugin
	if (!plugin_default_version_check (version, &gcc_version))
	{
		std::cerr << "This GCC plugin is for version " << GCCPLUGIN_VERSION_MAJOR << "." << GCCPLUGIN_VERSION_MINOR << "\n";
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
			fout.open(outfile_path, std::ios::app);
		}
		if(strcmp(plugin_info->argv[i].key, "debug") == 0) {
			flowana_debug = true;
		}
	}

	// Register the phase right after cfg
	struct register_pass_info pass_info;

#if BUILDING_GCC_VERSION >= 4009
	pass_info.pass = new flow_pass(g); // "g" is a global gcc::context pointer
#else
	pass_info.pass = &flow_pass.pass;
#endif
	pass_info.reference_pass_name = "einline";
	//pass_info.reference_pass_name = "release_ssa";
	pass_info.ref_pass_instance_number = 1;
	pass_info.pos_op = PASS_POS_INSERT_AFTER;

	register_callback(plugin_info->base_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &pass_info);

	return 0;
}

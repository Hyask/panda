/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Andrew Fasano               andrew.fasano@ll.mit.edu
 *  Nick Gregory                ngregory@nyu.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */

// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"
#include "hooks_int_fns.h"
#include <iostream>
#include <unordered_map>
#include <vector>

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C"
{
    bool init_plugin(void *);
    void uninit_plugin(void *);
}

using namespace std;

// Hooking framework to execute code before guest executes given basic block

// Mapping of addresses to hook functions
unordered_map<target_ulong, vector<pair<target_ulong, hook_func_t>>> hooks;

// Callback object
panda_cb c_callback;

// Handle to self
void *self = NULL;

// Enable and disable callbacks
void enable_hooking()
{
    assert(self != NULL);
    panda_enable_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, c_callback);
}
void disable_hooking()
{
    assert(self != NULL);
    panda_disable_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, c_callback);
}

void update_hook(hook_func_t hook, target_ulong value)
{
    update_hook_asid(hook,value,0);
}

void update_hook_asid(hook_func_t hook, target_ulong value, target_ulong asid){
    for (auto it = hooks.begin(); it != hooks.end(); ++it)
    {
        if (it->first == value)
            continue;
        vector<pair<target_ulong,hook_func_t>> hook_pile = it->second;
        auto i = hook_pile.begin();
        while (i != hook_pile.end())
        {
            auto element = *i;
            if (hook == element.second)
            {
                i = hook_pile.erase(i);
            }
            else
            {
                ++i;
            }
        }
        it->second = hook_pile;
    }
    pair<target_ulong, hook_func_t> hook_pairs = make_pair(asid, hook);
    hooks[value].push_back(hook_pairs);
}

void enable_hook(hook_func_t hook, target_ulong value)
{
    update_hook(hook, value);
}

void disable_hook(hook_func_t hook)
{
    for (auto it = hooks.begin(); it != hooks.end(); ++it)
    {
        vector<pair<target_ulong, hook_func_t>> hook_pile = it->second;
        auto i = hook_pile.begin();
        while (i != hook_pile.end())
        {
            auto p = *i;
            if (hook == p.second)
            {
                i = hook_pile.erase(i);
            }
            else
            {
                ++i;
            }
        }
        it->second = hook_pile;
    }
}

void add_hook(target_ulong addr, hook_func_t hook)
{
    printf("Adding hook from guest 0x" TARGET_FMT_lx " to host %p\n", addr, hook);
    add_hook_asid(addr, hook, 0);
}

void add_hook_asid(target_ulong addr, hook_func_t hook, target_ulong cr3)
{
    if (!panda_is_callback_enabled(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, c_callback))
        enable_hooking(); // Ensure our panda callback is enabled when we add a hook
                          // check for existing hook
    vector<pair<target_ulong, hook_func_t>> hook_pile = hooks[addr];
    for (auto it = hook_pile.begin(); it != hook_pile.end(); ++it)
    {
        pair<target_ulong, hook_func_t> element = *it;
        if (element.second == hook)
        {
            return;
        }
    }
    pair<target_ulong, hook_func_t> to_add = make_pair(cr3, hook);
    hooks[addr].push_back(to_add);
}

// The panda callback to determine if we should call a python callback
bool before_block_exec_invalidate_opt(CPUState *cpu, TranslationBlock *tb)
{
    // Call any callbacks registered at this PC. Any called callback may invalidate the translation block

    bool ret = false;

    auto func_hooks = hooks.find(tb->pc);
    if (func_hooks != hooks.end())
    {
        target_ulong asid = panda_current_asid(cpu);
        for (auto &hook : func_hooks->second)
        {
            if (asid == hook.first || hook.first == 0){
                ret |= (*hook.second)(cpu, tb);
            }
        }
    }
#ifdef DEBUG
    if (ret)
    {
        printf("Invalidating the translation block at 0x" TARGET_FMT_lx "\n", tb->pc);
    }
#endif

    return ret;
}

bool init_plugin(void *_self)
{
    // On init, register a callback but don't enable it
    self = _self;

    panda_disable_tb_chaining();

    c_callback.before_block_exec_invalidate_opt = before_block_exec_invalidate_opt;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, c_callback);
    panda_disable_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, c_callback);

    panda_enable_memcb();

    return true;
}

void uninit_plugin(void *self) {}

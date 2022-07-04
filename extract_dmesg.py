#!/usr/bin/env python3
from common import *

import collections
import hexdump
import sys
import itertools
import elfview

from ctypes import Structure, c_uint8, c_uint16, c_uint32, c_uint64, sizeof

class Printk_Log(Structure):
    _fields_ = [
        ("ts_nsec", c_uint64),
        ("len", c_uint16),
        ("text_len", c_uint16),
        ("dict_len", c_uint16),
        ("facility", c_uint8),
        ("flags", c_uint8),
    ]
    def __repr__(self):
        return " ".join("{}:{}".format(x[0], hex(getattr(self, x[0]))) for x in self._fields_)

class combined_printk:
    @staticmethod
    def yield_buffer_entries(buf, *_):
        while len(buf) > sizeof(Printk_Log):
            entry = Printk_Log.from_buffer_copy(buf)
            if entry.len == 0:
                break
            if entry.len > len(buf): # Can't yield the entire entry
                break
            yield entry, buf[:entry.len]
            buf = buf[entry.len:]

    @staticmethod
    def get_text_from_entry(buf, entry, *_):
        return buf[sizeof(entry):sizeof(entry) + entry.text_len]

    @staticmethod
    def get_info(entry, view):
        return entry # inline

    @staticmethod
    def sanity_check(buf, entry, *_):
        if entry.text_len + entry.dict_len > entry.len:
            return False
        if entry.text_len:
            try:
                combined_printk.get_text_from_entry(buf, entry).decode()
            except UnicodeDecodeError:
                return False
        return True

# New style Log-Records since ~ 5.X: __log_buf is now the text ring buffer.
class split_printk:
    @staticmethod
    def yield_buffer_entries(buf, view):
        first = True
        while len(buf) > view.pointer_size:
            seq_id = decode_pointer(buf[:view.pointer_size], view)
            if seq_id == 0:
                if not first:
                    break
                first = False
            # Try to take until \x00 and align
            text = bytes(itertools.takewhile(lambda byte: byte != 0, buf[view.pointer_size:]))
            length = len(text) + view.pointer_size
            length = length if length % view.pointer_size == 0 else length + view.pointer_size - (length % view.pointer_size)
            # but also try to find the next seq_id
            next_seq = struct.pack(view.byte_order + pointer_struct_size(view), seq_id + 1)
            next_seq_loc = buf.find(next_seq)
            if next_seq_loc < length:
                text = text[:next_seq_loc - view.pointer_size]
                length = next_seq_loc
            text = text.rstrip(b'\0')
            entry = (seq_id, text)
            yield (entry, None)
            buf = buf[length:]

    @staticmethod
    def get_text_from_entry(buf, entry, view):
        return entry[1]

    @staticmethod
    def get_info(entry, view):
        return entry[0]

    @staticmethod
    def sanity_check(buf, entry, view):
        try:
            if entry[0] >= (1 << 48):
                return False
            entry[1].decode()
            return True
        except (NotMapped, UnicodeDecodeError):
            return False

def is_valid_log_buffer(log_buf, view, mode):
    if log_buf < 0x1000:
        return False
    try:
        sample = view.get_virt(log_buf, 0x1000)
        # print("Sample:", sample)
        count = 0
        for entry, chunk in mode.yield_buffer_entries(sample, view):
            if not mode.sanity_check(chunk, entry, view):
                return False
            if entry.text_len != 0:
                # Non-empty entry with valid text!
                return True
        return False
    except NotMapped:
        return False

if __name__ == "__main__":
    def parser_setup(parser):
        parser.add_argument('-5', '--linux-5', help='New kernels have a different dmesg layout', action='store_true')
    args, _, view = tool_setup(parser_setup, layout_optional=True)
    mode = split_printk if args.linux_5 else combined_printk

    log_buf_addr = view.lookup_symbol('__log_buf')
    log_buf_ptr_addr = view.lookup_symbol('log_buf')
    if log_buf_addr is None and log_buf_ptr_addr is not None:
        print(f'\x1b[33mResolving __log_buf via log_buf ({log_buf_ptr_addr:#x})\x1b[0m')
        if is_valid_log_buffer(pointer(log_buf_ptr_addr, view), view, mode):
            log_buf_addr = pointer(log_buf_ptr_addr, view)
        elif is_valid_log_buffer(log_buf_ptr_addr, view, mode):
            log_buf_addr = log_buf_ptr_addr
        else:
            candidates = view.lookup_symbol('log_buf', all=True)
            for addr in candidates:
                try:
                    deref = pointer(addr, view)
                except NotMapped:
                    continue
                if is_valid_log_buffer(deref, view, mode):
                    log_buf_addr = deref
                    break
                elif is_valid_log_buffer(addr, view, mode):
                    log_buf_addr = addr # Just in case the compiler inlined the pointer deref to a constant...
                    break
        if log_buf_addr:
            print(f'\x1b[33mResolved to {log_buf_addr:#x}\x1b[0m')
    assert log_buf_addr, 'Log buffer (symbol __log_buf) not found'

    adjust_size = None
    try:
        log_buf_len_addr = view.lookup_symbol('log_buf_len')
        if log_buf_len_addr is None:
            print('Symbol log_buf_len not found, assuming default (64KB, via CONFIG_LOG_BUF_SHIFT)')
            log_buf_len = 1 << 17
            adjust_size = True
        else:
            log_buf_len = u32(log_buf_len_addr, view)
            adjust_size = False
    except NotMapped:
        log_buf_len = 1 << 17
        adjust_size = True
    print(f'Buffer address: {log_buf_addr:#x}')
    print(f'Buffer length:  {log_buf_len:#x}')
    #assert 0 < log_buf_len <= (1 << 21), 'Unreasonable log buffer size' # Config allows up to 1 << 21.
    if log_buf_len > (1 << 21):
        log_buf_len = (1 << 21)

    while adjust_size and log_buf_len > 0x1000:
        # If we guessed the size, be prepared to shrink it in case of missing mappings
        try:
            log_buf = view.get_virt(log_buf_addr, log_buf_len)
            break
        except NotMapped:
            log_buf_len //= 2
    log_buf = view.get_virt(log_buf_addr, log_buf_len)

    messages = ""

    for entry, chunk in mode.yield_buffer_entries(log_buf, view):
        if not mode.sanity_check(chunk, entry, view):
            print(f'\x1b[33mInvalid entry: {entry}\x1b[0m')
            continue
        meta = mode.get_info(entry, view)
        text = mode.get_text_from_entry(chunk, entry, view).decode()
        try:
            msg = "[{}, Lvl {}] {}".format(meta.ts_nsec / 10e8, meta.flags & 0b111, text)
        except AttributeError:
            msg = "[{:8x}] {}".format(meta, text)
        print(msg)
        messages += msg + "\n"

    with open("{}-dmesg".format(args.image), "w") as f:
        f.write("{}\n".format(messages))

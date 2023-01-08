#!/usr/bin/env python3
# (c) 2022 Felipe Correa da Silva Sanches <juca@members.fsf.org>
# Licensed under GPL version 3 or later


import sys

def hex8(v):
    return "0x%02X" % v
 
def hex16(v):
    return "0x%04X" % v

class CodeBlock():
    ''' A code block represents an address range in
        program memory. The range is specified by
        the self.start and self.end values.

        If a code block ends with a ret (return) instruction,
        then self.next_block will remain an empty list.

        Otherwise, it may have a single-element corresponding
        to a JMP instruction or a couple of values for each of
        the possible execution paths for a conditional branching
        instruction.
    '''

    def __init__(self, start, end, next_block=[], needs_label=False):
        self.start = start
        self.end = end
        self.subroutines = {}
        self.next_block = next_block
        self.needs_label = needs_label

    def add_subroutine_call(self, instr_address, routine_address):
        self.subroutines[instr_address] = routine_address


ERROR = 0   # only critical messages
VERBOSE = 1 # informative non-error msgs to the user
DEBUG = 2   # debugging messages to the developer


class AddressAlreadyVisited(Exception):
    pass


class ExecTrace():
    """ ExecTrace is a generic class that implements an
        algorithm for mapping all reachable code-paths
        in a given binary.

        As a sub-product it can also emit:
        (1) a disassembly listing
        (2) a flow-chart
        (3) a map of code-regions versus data-regions

        This class must be inherited by a child-class
        providing a disasm_instruction method which
        (a) uses self.fetch() to read consecutive bytes from
        code memory
        (b) returns a string representing the disassembly of
        the current instruction
        (c) invokes the class methods listed below to declare
        the behaviour of the branching instructions.

        Instruction description methods:
          * subroutine(address)
             Declares that the current instruction
             invokes a subroutine at <address>

          * return_from_subroutine()
             Declares that the current instruction
             terminates the execution of a subroutine
             and jumps back to the code that originally
             invoked the subroutine.

          * conditional_branch(address)
             Declares that the current instruction
             is a conditional branch that may
             jump to <address>

          * unconditional_jump(address)
             Declares that the current instruction
             is an unconditional jump to <address>

          * illegal_instruction(opcode)
             Declares that the current instruction
             with operation code <opcode> could not
             be parsed as a valid known instruction.
    """
    def __init__(self,
                 romfile,
                 rombank=0,
                 loglevel=ERROR,
                 relocation_blocks=None,
                 variables={},
                 subroutines={}):
        self.loglevel = loglevel
        self.rombank = rombank
        self.relocation_blocks = relocation_blocks
        self.variables = variables
        self.subroutines = subroutines
        self.visited_ranges = []
        self.pending_labeled_entry_points = []
        self.pending_unlabeled_entry_points = []
        self.pending_entry_points = []
        self.current_entry_point = None
        self.PC = None
        self.disasm = {}
        self.labeled_addresses = []

        self.read_rom(romfile)

        to_register = []
        for var_addr, var in self.variables.items():
            self.register_label(var[0])
            if var[1] in ["jump_table", "pointers"]:
                for i in range(var[2]):
                    ptr = self.read_word(var_addr + 2*i)
                    to_register.append(ptr)
                    if var[1] == "jump_table":
                        self.pending_entry_points.append(ptr)

        for ptr in to_register:
            print("Register pointer %04X" % ptr)
            if ptr not in self.variables.keys():
                self.variables[ptr] = ("LABEL_%04X" % ptr, "label")
            self.register_label(ptr)

        for subr_addr in self.subroutines.keys():
            self.register_label(subr_addr)


    def read_word(self, addr):
        value = self.read_byte(addr)
        value = value | (self.read_byte(addr+1) << 8)
        return value


    def read_byte(self, addr):
        reloc_index, physical_address = self.rom_address(addr)
        return self.rom[reloc_index][physical_address]


    def register_label(self, address):
      if address not in self.labeled_addresses:
        self.labeled_addresses.append(address)


    def read_rom(self, filename):
        rom_file = open(filename, "rb")
        if self.relocation_blocks:
            self.rom = []
            for reloc_from, reloc_to, length in self.relocation_blocks:
                rom_file.seek(reloc_from)
                binary_data = rom_file.read(length)
                self.rom.append(binary_data)
        else:
            self.rom = [rom_file.read()]
            self.relocation_blocks = (0x0000, 0x0000, len(self.rom[0]))
        rom_file.close()


### Public method to start the binary code interpretation ###
    def run(self, entry_points=[0x0000]):
        self.pending_entry_points.extend(entry_points)
        self.all_entry_points = [p for p in self.pending_entry_points]
        self.current_entry_point = self.pending_entry_points.pop(0)
        self.current_entry_point_needs_label = True
        self.PC = self.current_entry_point
        self.register_label(self.current_entry_point)
        while self.PC is not None:
            address = self.PC
            try:
                opcode = self.fetch()
                self.disasm[address] = self.disasm_instruction(opcode)
                self.log(DEBUG, hex(address) + ": " + self.disasm[address])
            except AddressAlreadyVisited:
                self.log(VERBOSE, "ALREADY BEEN AT {}!".format(hex(self.PC)))
                self.log(DEBUG, "pending_entry_points: {}".format(self.pending_entry_points))
                if self.PC > self.current_entry_point:
                    self.add_range(start=self.current_entry_point,
                                   end=self.PC-1,
                                   needs_label=self.current_entry_point_needs_label,
                                   exit=[self.PC])
                self.restart_from_another_entry_point()


    def getVariableName(self, addr):
        if addr in self.variables.keys():
            return self.variables[addr][0]
        else:
            return hex16(addr)


    def getLabelName(self, addr, prefix="LABEL_"):
        if addr in self.variables.keys():
            return self.variables[addr][0]
        elif addr in self.subroutines.keys():
            return self.subroutines[addr][0]
        else:
            return "%s%04X" % (prefix, addr)


### Methods for declaring the behaviour of branching instructions ###
    def subroutine(self, address):
        self.add_range(start=self.current_entry_point,
                       end=self.PC-1,
                       exit=[self.PC, address],
                       needs_label=self.current_entry_point_needs_label)
        self.schedule_entry_point(self.PC, needs_label=False)
        self.schedule_entry_point(address, needs_label=True)

        self.log(VERBOSE, "CALL SUBROUTINE ({})".format(hex(address)))
        self.log_status()
        self.restart_from_another_entry_point()

    def return_from_subroutine(self):
        self.add_range(start=self.current_entry_point,
                       end=self.PC-1,
                       exit=[],
                       needs_label=self.current_entry_point_needs_label)
        self.log(VERBOSE, "RETURN FROM SUBROUTINE")
        self.log_status()
        self.restart_from_another_entry_point()

    def conditional_branch(self, address):
        self.log(VERBOSE, "CONDITIONAL BRANCH to {}".format(hex(address)))
        self.branch(address, conditional=True)

    def unconditional_jump(self, address):
        self.log(VERBOSE, "UNCONDITIONAL JUMP to {}".format(hex(address)))
        self.branch(address, conditional=False)

    def branch(self, address, conditional):
        if address > self.current_entry_point and address < self.PC:
            self.add_range(start=self.current_entry_point,
                           end=address-1,
                           exit=[address],
                           needs_label=self.current_entry_point_needs_label)
            self.add_range(start=address,
                           end=self.PC-1,
                           exit=[self.PC, address],
                           needs_label=True)
            if conditional:
                self.schedule_entry_point(self.PC, needs_label=False)
        else:
            self.add_range(start=self.current_entry_point,
                           end=self.PC-1,
                           exit=[self.PC, address],
                           needs_label=self.current_entry_point_needs_label)
            if conditional:
                self.schedule_entry_point(self.PC, needs_label=False)
            self.schedule_entry_point(address, needs_label=True)

        self.log_ranges()
        self.restart_from_another_entry_point()

    def illegal_instruction(self, opcode):
        self.add_range(start=self.current_entry_point,
                       end=self.PC-1,
                       exit=["Illegal Opcode: {}".format(hex(opcode))],
                       needs_label=self.current_entry_point_needs_label)
        self.log(ERROR, "[{}] ILLEGAL: {}".format(hex(self.PC-1), hex(opcode)))
        self.PC = None  # This will finish the crawling
        # sys.exit(-1)

### Private methods for computing the code-execution graph structure ###
    def already_visited(self, address):
        if self.PC is not None:
            if address >= self.current_entry_point and address < self.PC:
                self.log(DEBUG, "RECENTLY: (PC={} address={})".format(hex(self.PC), hex(address)))
                return True

        for codeblock in self.visited_ranges:
            if address >= codeblock.start and address <= codeblock.end:
                self.log(DEBUG, "ALREADY VISITED: {}".format(hex(address)))
                if address > codeblock.start:
                    # split the block into two:
                    new_block = CodeBlock(start=codeblock.start,
                                          end=address-1,
                                          next_block=[address],
                                          needs_label=codeblock.needs_label)
                    codeblock.start = address
                    codeblock.needs_label = True
                    # and also split ownership of subroutine calls:
                    for instr_addr, call_addr in codeblock.subroutines.items():
                        if instr_addr < address:
                            new_block.add_subroutine_call(instr_addr, call_addr)
                            del codeblock.subroutines[instr_addr]
                    self.visited_ranges.append(new_block)
                return True

        # otherwise:
        return False

    def restart_from_another_entry_point(self):
        if len(self.pending_labeled_entry_points) == 0 and len(self.pending_unlabeled_entry_points) == 0:
            self.PC = None  # This will finish the crawling
        else:
            if len(self.pending_labeled_entry_points) > 0:
                address = self.pending_labeled_entry_points.pop()
                self.current_entry_point_needs_label = True
            else:
                address = self.pending_unlabeled_entry_points.pop()
                self.current_entry_point_needs_label = False

            self.current_entry_point = address
            self.PC = address
            self.log(VERBOSE, "Restarting from: {}".format(hex(address)))

    def add_range(self, start, end, needs_label, exit=None):
        if end < start:
            self.add_range(end, start, exit, needs_label)
            return

        self.log(DEBUG, f"=== New Range: start: {hex(start)}  end: {hex(end)} needs_label: {needs_label}===")
        block = CodeBlock(start, end, exit, needs_label)
        self.visited_ranges.append(block)

    def schedule_entry_point(self, address, needs_label):
        if self.already_visited(address):
            #FIXME: I think the same address can be referenced needing a label
            # even after it was already visited once not originally needing a label.
            return

        if needs_label:
            if address not in self.pending_labeled_entry_points:
                self.pending_labeled_entry_points.append(address)
        else:
            if address not in self.pending_unlabeled_entry_points:
                self.pending_unlabeled_entry_points.append(address)

        self.log(VERBOSE, "SCHEDULING: {}".format(hex(address)))
        self.log_status()


    def increment_PC(self):
        if self.already_visited(self.PC):
            self.log(VERBOSE, "ALREADY BEEN AT {}!".format(hex(self.PC)))
            self.log(DEBUG, "pending_labeled_entry_points: {}".format(self.pending_labeled_entry_points))
            self.log(DEBUG, "pending_unlabeled_entry_points: {}".format(self.pending_unlabeled_entry_points))
            self.add_range(start=self.current_entry_point,
                           end=self.PC-1,
                           exit=[self.PC],
                           needs_label=self.current_entry_point_needs_label)
            self.restart_from_another_entry_point()
            return -1
        else:
            self.PC += 1


    def fetch(self):
        if self.already_visited(self.PC):
            raise AddressAlreadyVisited
        else:
            try:
                index, offset = self.rom_address(self.PC)
                value = self.rom[index][offset]
            except:
                #print("ROM index = %d / offset = %04X" % (index, offset))
                sys.exit("Cannot fetch at PC=%s" % hex16(self.PC))

            self.log(DEBUG, "Fetch at {}: {}".format(hex(self.PC), hex(value)))
            self.PC += 1
        return value



####### LOGGING #######
    def log(self, loglevel, msg):
        if self.loglevel >= loglevel:
            print(msg)

    def log_status(self):
        self.log(VERBOSE, "Pending labeled: {}".format(list(map(hex, self.pending_labeled_entry_points))))
        self.log(VERBOSE, "Pending unlabeled: {}".format(list(map(hex, self.pending_unlabeled_entry_points))))

    def log_ranges(self):
        results = []
        for codeblock in sorted(self.visited_ranges, key=lambda cb: cb.start):
            results.append("[start: {}, end: {}]".format(hex(codeblock.start),
                                                         hex(codeblock.end)))
        self.log(DEBUG, "ranges:\n  " + "\n  ".join(results) + "\n")
#######################

    def print_grouped_ranges(self):
        results = []
        grouped = self.get_grouped_ranges()
        for codeblock in grouped:
            results.append("[start: {}, end: {}]".format(hex(codeblock[0]),
                                                         hex(codeblock[1])))
        print ("code ranges:\n  " + "\n  ".join(results) + "\n")

    def get_grouped_ranges(self):
        grouped = []
        current = None
        for codeblock in sorted(self.visited_ranges, key=lambda cb: cb.start):
            if current == None:
                current = [codeblock.start, codeblock.end]
                continue

            # FIX-ME: There's something bad going on here!!!
            if codeblock.start == current[1] or \
               codeblock.start == (current[1] + 1):
                current[1] = codeblock.end
                continue
#      print (">>> codeblock.start: {} current[1]: {}\n".format(hex(codeblock.start),
#                                                               hex(current[1])))
            grouped.append(current)
            current = [codeblock.start, codeblock.end]
            return grouped


    def rom_address(self, logical_address):
        for index, reloc in enumerate(self.relocation_blocks):
            reloc_from, reloc_to, length = reloc
            if (logical_address >= reloc_to and
                logical_address < reloc_to + length):
                offset = logical_address - reloc_to
                return index, offset
        sys.exit("The logical address %04X was not found on any relocation block." % logical_address)


    def save_disassembly_listing(self, filename="output.asm"):

        var_addrs = sorted(self.variables.keys())

        self.next_var = -1
        def select_next_var_address(addr):
            for var in var_addrs:
                if var >= addr:
                    self.next_var = var
                    return

        asm = open(filename, "w")
        asm.write(self.output_disasm_headers())

        for reloc_from, reloc_to, reloc_length in self.relocation_blocks:
            ranges = [r for r in sorted(self.visited_ranges, key=lambda cb: cb.start)
                      if r.start >= reloc_to and r.end < reloc_to + reloc_length]

            asm.write("\n\n\torg %s\n" % hex16(reloc_to))
            next_addr = reloc_to

            # This is a hack to make the disasm output the final
            # block of data in the end of a ROM image:
            ranges.append(CodeBlock(start=reloc_to + reloc_length,
                                    end=-1,
                                    next_block=[]))

            for codeblock in ranges:
                if codeblock.start < next_addr: # Skip repeated blocks!
                    continue

                if codeblock.start > next_addr: # there's a block of data here
                    indent = self.getLabelName(next_addr) + ":\n\t"
                    data = []
                    addr = next_addr
                    while addr < codeblock.start:
                        select_next_var_address(addr)
                        if addr == self.next_var:
                            if len(data) > 0:
                                asm.write("{}db {}\n".format(indent, ", ".join(data)))
                                data = []
                            var = self.variables[self.next_var]
                            indent = "%s:\n\t" % var[0]
#============================================================================
                            if var[1] == "str":
                                n = var[2]
                                the_string = ""
                                for i in range(n):
                                    reloc_index, physical_address = self.rom_address(addr)
                                    the_string += chr(self.rom[reloc_index][physical_address])
                                    addr += 1
                                asm.write('{}db "{}"\n'.format(indent, the_string))
                                indent = self.getLabelName(addr) + ":\n\t"
                                data = []
                                continue
#============================================================================
                            elif var[1] == "n-1_str":
                                reloc_index, physical_address = self.rom_address(addr)
                                n = self.rom[reloc_index][physical_address]
                                the_string = ""
                                addr += 1
                                for i in range(n-1):
                                    reloc_index, physical_address = self.rom_address(addr)
                                    the_string += chr(self.rom[reloc_index][physical_address])
                                    addr += 1
                                asm.write('{}db {}, "{}"\n'.format(indent, n, the_string))
                                indent = self.getLabelName(addr) + ":\n\t"
                                data = []
                                continue
#============================================================================
                            if var[1] in ["jump_table", "pointers"]:
                                n = var[2]
                                asm.write("\n")
                                for i in range(n):
                                    reloc_index, physical_address = self.rom_address(addr)
                                    jump_addr = self.rom[reloc_index][physical_address]
                                    addr += 1
                                    reloc_index, physical_address = self.rom_address(addr)
                                    jump_addr = jump_addr | (self.rom[reloc_index][physical_address] << 8)
                                    addr += 1
                                    asm.write('{}dw {}\n'.format(indent, self.getLabelName(jump_addr)))
                                    indent = "\t"
                                indent = self.getLabelName(addr) + ":\n\t"
                                data = []
                                continue
#============================================================================
                        try:
                            reloc_index, physical_address = self.rom_address(addr)
                        except:
                            if len(data) > 0:
                                asm.write("{}db {}\n".format(indent, ", ".join(data)))
                                data = []
                                addr += 1
                            continue

                        try:
                            data.append(hex8(self.rom[reloc_index][physical_address]))
                        except:
                            sys.exit("reloc_index={} physical_address={} rom_data_len={}".format(reloc_index,
                                                                                                 physical_address,
                                                                                                 len(self.rom[reloc_index])))
                        if len(data) == 8:
                            asm.write("{}db {}\n".format(indent, ", ".join(data)))
                            indent = "\t"
                            data = []
                        addr += 1

                    if len(data) > 0:
                        asm.write("{}db {}\n".format(indent, ", ".join(data)))

                # TODO: Maybe we need to ensure codeblocks do not cross relocation block boundaries
                #       If so, we may need to split them at the boundaries.
                address = codeblock.start
                if address in self.labeled_addresses:
                    indent = "\n" + self.getLabelName(address) + ":\n\t"
                else:
                    indent = "\t"
                for address in range(codeblock.start, codeblock.end+1):
                    if address in self.disasm:
                        asm.write("%s%s\n" % (indent, self.disasm[address]))
                        indent = "\t"
                next_addr = codeblock.end + 1

        asm.close()


def generate_graph():
    def block_name(block):
        return "{}-{}".format(hex(block.start), hex(block.end))

    import pydotplus
    graph = pydotplus.graphviz.Graph(graph_name='Code Execution Graph',
                             graph_type='digraph',
                             strict=False,
                             suppress_disconnected=False)
    graph_dict = {}
    for block in self.visited_ranges:
        node = pydotplus.graphviz.Node(block_name(block))
        graph.add_node(node)
        graph_dict[block.start] = node

    for block in self.visited_ranges:
        for nb in block.next_block:
            if nb is str:
                print (nb)  # this must be an illegal instruction
            else:
                if nb in graph_dict.keys():
                    edge = pydotplus.graphviz.Edge(graph_dict[block.start], graph_dict[nb])
                    graph.add_edge(edge)
                else:
                    print (f"Missing codeblock: {hex(nb)}")

    open("output.gv", "w").write(graph.to_string())

    #from graphviz import Digraph
    #dot = Digraph(comment='Code Execution Graph')
    #dot.render('test-output/round-table.gv', view=True)


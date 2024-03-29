import readline

from console.screen import sc
from console.utils import *
from console.viewers import hprint as print
from console import fg, bg, fx
from ftraceparser.trace import *

MAX_LINES = 1000000000
class Terminal(Trace):
    def __init__(self, file):
        super().__init__()
        self.file = file
        self._regx_cmd_find = r'^(find|findall|findexact) ([A-Za-z0-9_.]+)( ((in func \d+)|(between (\d+|begin) and (\d+|end))))?'
        self._regx_cmd_caller = r'^caller (\d+)'
        self._regx_cmd_callee = r'^callee (\d+)'
        self._regx_cmd_entry = r'^entry'
        self._regx_cmd_pdn = r'^pdn(\d+)? (\d+)(\/(\d+))?'
        self._regx_cmd_pdf = r'^pdf (\d+)(\/(\d+))?'
        self._regx_cmd_block = r'^block'
        self._regx_cmd_delete = r'^delete'
        self._regx_cmd_filter = r'^filter(( .+)|$)'
        self._regx_cmd_filter_delete = r'^filter-d'
        self._regx_cmd_clear = r'^clear'
        self._regx_cmd_show = r'^show(\d+)? (\d+)'
        self._regx_cmd_export_func = r'^export-func (\d+) ([\w./\\-]+)$'
        self._regx_cmd_compare = r'^compare (\d+) ([\w./\\-]+)( (\d+))?$'

    def run(self):
        tmp_filter = []

        set_title("Ftrace Parser")
        self.load_tracefile(self.file)
        self.serialize()
        while True:
            if tmp_filter != []:
                for each in tmp_filter:
                    self.remove_filter_inst(each[0], each[1])
                tmp_filter = []
            try:
                command = input('ftrace-parser> ')
            except KeyboardInterrupt:
                print('\nexit ftrace-parser by exit() or Ctrl-D')
                continue
            except EOFError:
                exit(0)
            if command == 'exit':
                exit(0)
            if command == 'help':
                self.print_help()
                continue
            
            if command.find('|') != -1:
                t = command.split('|')
                if len(t) > 2:
                    self._error('unkown format for filter')
                    continue
                command = t[0]
                filter_cmd = t[1]
                tmp_filter = self.build_temp_filter(filter_cmd)

            # find | findall | findexact
            if regx_match(self._regx_cmd_find, command):
                self.cmd_find(command)
                continue
                
            # caller
            if regx_match(self._regx_cmd_caller, command):
                self.cmd_caller(command)
                continue
            
            # callee
            if regx_match(self._regx_cmd_callee, command):
                self.cmd_callee(command)
                continue

            # entry
            if regx_match(self._regx_cmd_entry, command):
                self.cmd_entry(command)
                continue
            
            # pdn
            if regx_match(self._regx_cmd_pdn, command):
                self.cmd_pdn(command)
                continue
            
            # pdf
            if regx_match(self._regx_cmd_pdf, command):
                self.cmd_pdf(command)
                continue

            # block
            if regx_match(self._regx_cmd_block, command):
                self.cmd_block(command)
                continue
            
            # delete
            if regx_match(self._regx_cmd_delete, command):
                self.cmd_delete(command)
                continue
            
            # filter
            if regx_match(self._regx_cmd_filter, command):
                self.cmd_filter(command)
                continue
            
            # filter-d
            if regx_match(self._regx_cmd_filter_delete, command):
                self.cmd_filter_delete(command)
                continue

            # clear
            if regx_match(self._regx_cmd_clear, command):
                self.cmd_clear()
                continue
            
            # show
            if regx_match(self._regx_cmd_show, command):
                self.cmd_show(command)
                continue
                
            # export-func
            if regx_match(self._regx_cmd_export_func, command):
                self.cmd_export_func(command)
                continue
            
            # compare
            if regx_match(self._regx_cmd_compare, command):
                self.cmd_compare(command)
                continue
    
    def print_help(self):
        print('''
        help: show this help
        exit: exit ftrace-parser
        find | findall | findexact: find a node by name
        findall: find info in trace, and show all occurrences
        caller: show caller of a node
        callee: show callee of a node
        entry: show entry of a node
        pdn[length] (node_id)\[level]: show pdn of a node
        pdf (node_id)\[level]: show pdf of a node
        block (func): block a node from printing
        delete (func): delete a block rule
        filter: filter trace
        filter-d: delete filter
        clear: clear terminal
        show[length] (node_id): show one more multiple nodes in chronological manner
        export-func (node_id) (file): export a function trace to a file
        ''')

    def cmd_find(self, command):
        in_regx = r'in func (\d+)'
        between_regx = r'between (\d+|begin) and (\d+|end)'
        m = regx_getall(self._regx_cmd_find, command)[0]
        start_node = None
        end_node = None
        findall = False
        findexact = False
        in_func = False
        find_mode = m[0]
        info = m[1]
        if len(m) > 2:
            extra = m[3]
            if regx_match(in_regx, extra):
                n_id = regx_get(in_regx, extra, 0)
                func = self.find_node(int(n_id))
                in_func = True
                start_node = func.scope_begin_node
                end_node = func.scope_end_node
            if regx_match(between_regx, extra):
                n_id_s = regx_get(between_regx, extra, 0)
                n_id_e = regx_get(between_regx, extra, 1)
                if n_id_s != 'begin':
                    start_node = self.find_node(int(n_id_s))
                if n_id_e != 'end':
                    end_node = self.find_node(int(n_id_e))
        if find_mode.find('findall') != -1:
            findall = True
        if find_mode.find('exact') != -1:
            findexact = True
        res = self.find_info(info=info, find_all=findall, find_exact=findexact, start_node=start_node, end_node=end_node, in_func=in_func)
        for node in res:
            self.show_around(node)
        if findall or len(res) == 0:
            self._print_hightlight('find {} occurrences.'.format(len(res)))
            return

        while True:
            find_next = input('find next? (Y/n)')
            if find_next != 'n':
                res = self.find_info(info=info, start_node=res[-1], find_exact=findexact, end_node=end_node, in_func=in_func)
                if len(res) == 0:
                    break
                for node in res:
                    self.show_around(node)
            else:
                break
        return
    
    def cmd_caller(self, command):
        try:
            node_id = int(regx_get(r'caller (\d+)', command, 0))
        except ValueError:
            self._error('caller: invalid node id')
            return
        node = self.find_node(node_id)
        if node == None:
            self.logger.error('No such node: {}'.format(node_id))
            return
        if node.parent != None:
            self.print_banner()
            self.print_node(node.parent)
        else:
            self._print_hightlight('node {} is the top-level system call and it does not have a caller'.format(node_id))
        p_trace = input('print top-level trace? (N/y)')
        if p_trace == 'y':
            self.print_trace(node.parent.next_node, end_node=node, level=10)
        return
    
    def cmd_callee(self, command):
        try:
            node_id = int(regx_get(r'callee (\d+)', command, 0))
        except ValueError:
            self._error('callee: invalid node id')
            return
        node = self.find_node(node_id)
        if node == None:
            self.logger.error('No such node: {}'.format(node_id))
            return
        self.print_banner()
        self.print_trace(node, level=1, length=MAX_LINES, end_node=node.scope_end_node)
    
    def cmd_entry(self, command):
        try:
            m = regx_getall(r'entry (\d+)', command)
        except ValueError:
            self._error('syscall: invalid node id')
            return
        if len(m) > 0:
            node_id = int(m[0])
            node = self.find_node(node_id)
            if node == None:
                self.logger.error('No such node: {}'.format(node_id))
                return
            hop = self.get_hops_from_entry_node(node)
            node = self.find_node(hop.pop())
            self.print_banner()
            self.print_node(node)
            p_trace = input('print top-level trace? (N/y)')
            if p_trace == 'y':
                for each_node_id in hop[::-1]:
                    self.print_trace(node.next_node, end_node=self.find_node(each_node_id), level=0)
                    node = self.find_node(each_node_id)
        else:
            begin_node = self.find_node(0)
            self.print_banner()
            while begin_node != None:
                if begin_node.parent is None and begin_node.is_function:
                    self.print_node(begin_node, trim_bracket=True)
                begin_node = begin_node.next_node_by_time
    
    def cmd_pdn(self, command):
        try:
            m = regx_getall(self._regx_cmd_pdn, command)[0]
            if m[0] != '':
                n_lines = int(m[0])
            else:
                n_lines = 1
            node_id = int(m[1]) 
            if m[3] != '':
                level = int(m[3])
            else:
                level = 0
        except ValueError:
            self._error('pdn: invalid node id')
            return
        node = self.find_node(node_id)
        if node == None:
            self.logger.error('No such node: {}'.format(node_id))
            return
        self.print_banner()
        self.print_trace(node, level=level, length=n_lines)
        return
    
    def cmd_pdf(self, command):
        try:
            m = regx_getall(self._regx_cmd_pdf, command)[0]
            node_id = int(m[0])
            if m[2] == '':
                level = 1
            else:
                level = int(m[2])
        except ValueError:
            self._error('pdf: invalid node id')
            return
        node = self.find_node(node_id)
        if node == None:
            self.logger.error('No such node: {}'.format(node_id))
            return
        if not node.is_function:
            self._error('pdf: node {} is not a function begginning'.format(node_id))
            return
        self.print_banner()
        self.print_trace(node, level=level, length=MAX_LINES, end_node=node.scope_end_node)
    
    def cmd_block(self, command):
        try:
            m = regx_getall(r' ([A-Za-z0-9_.]+)', command)
            for each in m:
                if each not in self.blacklist:
                    self.blacklist.append(each)
        except ValueError:
            self._error('block: invalid function name')
            return
        if len(m) == 0:
            for each in self.blacklist:
                print(each)
    
    def cmd_delete(self, command):
        try:
            m = regx_getall(r' ([A-Za-z0-9_.]+)', command)
            for each in m:
                if each in self.blacklist:
                    self.blacklist.remove(each)
        except ValueError:
            self._error('block: invalid function name')
            return
        if len(m) == 0:
            self.blacklist = []
    
    def cmd_filter(self, command):
        if command == 'filter':
            self.show_filters()
            return
        try:
            m = regx_get(r'^filter by (.+)', command, 0)
            if m == None:
                self._error('filter: invalid arguments. [by task|by pid|by cpu|by time stamp|by event|by entry]')
                return
        except ValueError:
            self._error('filter: invalid arguments. [by task|by pid|by cpu|by time stamp|by event|by entry]')
            return
        exprs = m.split(' ')
        for each_expr in exprs:
            [_, index] = self.add_filter(each_expr)
            if index != -1:
                self._info('filter {}: {} added'.format(index, each_expr))
    
    def cmd_filter_delete(self, command):
        if command == 'filter-d':
            self.remove_filter_all()
            return
        try:
            m = regx_get(r'^filter-d (.+)', command, 0)
        except ValueError:
            self._error('filter-d: invalid arguments. [task|pid|cpu|time_stamp|event|entry]')
            return
        filters = m.split(' ')
        for each in filters:
            self.remove_filter(each)
    
    def cmd_export_func(self, command):
        try:
            m = regx_getall(self._regx_cmd_export_func, command)[0]
            if len(m) != 2:
                raise ValueError
            node_id = int(m[0])
            file = m[1]
        except ValueError:
            self._error('export-func: invalid arguments')
            return
        node = self.find_node(node_id)
        if node == None:
            self.logger.error('No such node: {}'.format(node_id))
            return
        if not node.is_function:
            self._error('pdf: node {} is not a function begginning'.format(node_id))
            return
        self.print_banner()
        nodes = self.gather_trace_nodes(node, level=MAX_LINES, end_node=node.scope_end_node)
        self.dump_to_json(file, nodes)
    
    def cmd_compare(self, command):
        try:
            m = regx_getall(self._regx_cmd_compare, command)[0]
            node_id = m[0]
            file = m[1]
            if len(m) == 4:
                level = int(m[3])
            else:
                level = -1
        except ValueError:
            self._error('compare: invalid arguments')
            return
        r_node = self.find_node(int(node_id))
        t_node = self.load_from_json(file)
        nodes_match_info = self.compare_nodes(r_node, t_node, level)
        for each in nodes_match_info:
            if each[0] == MATCH_NODE:
                self.print_node(each[1])
            elif each[0] == REFER_MISS_NODE:
                self.print_node(each[1], highlight=True)
            elif each[0] == TARGET_MISS_NODE:
                self.print_node(each[1], green=True)
        return
                
    def add_filter(self, expr):
        key = ''
        index = -1
        for each in ['<=', '>=', '==', "!=", '<', '>']:
            if expr.find(each) != -1:
                t = expr.split(each)
                key = t[0]
                data = t[1]
                if key != 'pid' and key != 'cpu' and (data[0] != '"' or data[-1] != '"'):
                    data = '"' + data + '"'
                if key in self.filter:
                    index = super().add_filter(key, each+data)
                else:
                    self._error('filter: invalid filter {}'.format(key))
        return [key, index]

    def build_temp_filter(self, filter_cmd):
        res = []
        exprs = filter_cmd.split(' ')
        for each_expr in exprs:
            [key, index] = self.add_filter(each_expr)
            if index != -1:
                res.append([key, index])
        return res
    
    def cmd_clear(self):
        reset_terminal()
    
    def cmd_show(self, command):
        try:
            m = regx_getall(self._regx_cmd_show, command)[0]
            if m[0] != '':
                n_lines = int(m[0])
            else:
                n_lines = 1
            node_id = int(m[1]) 
        except ValueError:
            self._error('show: invalid node id')
            return
        self.print_banner()
        for i in range(0, n_lines):
            node = self.find_node(node_id+i)
            if node is None:
                self._error('show: node {} not found'.format(node_id+i))
                break
            self.print_node(node)
    
    def show_around(self, node, deep=3, n=0):
        self.print_banner()
        self._show_nodes(node.prev_node, deep, 'prev', n+1)
        self.print_node(node, highlight=True)
        self._show_nodes(node.next_node, deep, 'next', n+1)
    
    def _show_nodes(self, node, deep, mode, n=0):
        if mode != 'next' and mode != 'prev':
            print('[_show_nodes]: mode must be either \'next\' or \'prev\'')
            return
        if node == None or n >= deep:
            return
        if n < deep:
            if mode == 'next':
                self.print_node(node)
                self._show_nodes(node.next_node, deep, mode, n+1)
            if mode == 'prev':
                self._show_nodes(node.prev_node, deep, mode, n+1)
                self.print_node(node)
        return
    
    def _print_hightlight(self, text):
        print(fg.red(text))
    
    def _error(self, text):
        self._print_hightlight(fg.red(text))
    
    def _info(self, text):
        print(fg.black(text))
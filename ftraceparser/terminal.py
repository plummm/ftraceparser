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
        self._regx_cmd_find = r'^(find|findall) ([A-Za-z0-9_.]+)( in task (\d+))?'
        self._regx_cmd_caller = r'^caller (\d+)'
        self._regx_cmd_callee = r'^callee (\d+)'
        self._regx_cmd_syscall = r'^syscall (\d+)'
        self._regx_cmd_pdn = r'^pdn(\d+)? (\d+)(\/(\d+))?'
        self._regx_cmd_pdf = r'^pdf (\d+)(\/(\d+))?'
        self._regx_cmd_block = r'^block'
        self._regx_cmd_delete = r'^delete'

    def run(self):
        set_title("Ftrace Parser")
        self.load_tracefile(self.file)
        self.serialize()
        while True:
            try:
                command = input('ftrace-parser> ')
            except KeyboardInterrupt:
                print('\nexit ftrace-parser by exit() or Ctrl-D')
            except EOFError:
                break
            if command == 'exit':
                break

            # find | findall
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

            # syscall
            if regx_match(self._regx_cmd_syscall, command):
                self.cmd_syscall(command)
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

    def cmd_find(self, command):
        m = regx_getall(r'(find|findall) ([A-Za-z0-9_.]+)( in task (\d+))?', command)[0]
        findall = False
        find_mode = m[0]
        info = m[1]
        task = m[3]
        if task == '':
            task = None
        else:
            task = int(task)
        if find_mode == 'findall':
            findall = True
        res = self.find_info(task=task, info=info, find_all=findall)
        for node in res:
            self.show_around(node)
        if findall or len(res) == 0:
            self._print_hightlight('find {} occurrences.'.format(len(res)))
            return

        while True:
            find_next = input('find next? (Y/n)')
            if find_next != 'n':
                res = self.find_info(task=task, info=info, start_node=res[-1])
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
        if node.parent != None:
            self.print_banner()
            self.print_node(node.parent)
        else:
            self._print_hightlight('node {} is the top-level system call and it does not have a caller'.format(node_id))
        p_trace = input('print top-level trace? (N/y)')
        if p_trace == 'y':
            self.print_trace(node.parent.next_node, end_node=node.id, level=10)
        return
    
    def cmd_callee(self, command):
        try:
            node_id = int(regx_get(r'callee (\d+)', command, 0))
        except ValueError:
            self._error('callee: invalid node id')
            return
        node = self.find_node(node_id)
        self.print_banner()
        self.print_trace(node, level=1, length=MAX_LINES)
    
    def cmd_syscall(self, command):
        try:
            node_id = int(regx_get(r'syscall (\d+)', command, 0))
        except ValueError:
            self._error('syscall: invalid node id')
            return
        node = self.find_node(node_id)
        hop = [node.id]
        while node.parent != None:
            node = node.parent
            hop.append(node.id)
        hop.pop()
        self.print_banner()
        self.print_node(node)
        p_trace = input('print top-level trace? (N/y)')
        if p_trace == 'y':
            for each_node_id in hop[::-1]:
                self.print_trace(node.next_node, end_node=each_node_id, level=0)
                node = self.find_node(each_node_id)
    
    def cmd_pdn(self, command):
        try:
            m = regx_getall(self._regx_cmd_pdn, command)[0]
            if m[0] == '':
                n_lines = int(m[0])
            else:
                n_lines = 1
            node_id = int(m[1]) 
            if m[3] != '':
                level = int(m[3])
            else:
                level = 0
        except ValueError:
            self._error('pd: invalid node id')
            return
        node = self.find_node(node_id)
        self.print_banner()
        self.print_trace(node, level=level, legnth=n_lines)
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
        if not node.is_function:
            self._error('pdf: node {} is not a function begginning'.format(node_id))
            return
        self.print_banner()
        self.print_trace(node, level=level, length=MAX_LINES)
    
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